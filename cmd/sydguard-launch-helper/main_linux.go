//go:build linux

// sydguard-launch-helper is a dedicated immutable, one-shot privileged launcher.
package main

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/managedstore"
	"github.com/Gobd/syd-guard/internal/session"
	"github.com/Gobd/syd-guard/internal/syd"
	"golang.org/x/sys/unix"
)

const (
	executable = "/usr/local/libexec/sydguard-launch-helper"
	registry   = "/var/lib/sydguard-policy"
	anchorBase = "/run/sydguard-launch"
)

type supervisorInput struct {
	ProjectID     string   `json:"project_id"`
	Name          string   `json:"name"`
	Revision      string   `json:"revision"`
	Profile       []byte   `json:"profile"`
	Engine        string   `json:"engine"`
	Home          string   `json:"home"`
	ConfigHome    string   `json:"config_home"`
	Args          []string `json:"args"`
	Project       string   `json:"project"`
	TemporaryRoot string   `json:"temporary_root"`
	SnapshotPath  string   `json:"snapshot_path"`
	RequirePIE    bool     `json:"require_pie"`
}

func main() {
	code, err := run()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sydguard launch:", err)
	}
	os.Exit(code)
}

func run() (int, error) {
	if len(os.Args) == 2 && os.Args[1] == "--supervise" {
		return supervise()
	}
	if len(os.Args) == 2 && os.Args[1] == "--watchdog" {
		if err := watchdogMain(); err != nil {
			return 1, err
		}
		return 0, nil
	}
	if len(os.Args) != 1 || os.Geteuid() != 0 {
		return 1, errors.New("invalid privileged launcher invocation")
	}
	startup := time.AfterFunc(20*time.Second, func() { os.Exit(124) })
	defer startup.Stop()
	if err := verifyInstallation(); err != nil {
		return 1, fmt.Errorf("untrusted launch installation: %w", err)
	}
	uid, err := sudoID("SUDO_UID")
	if err != nil {
		return 1, err
	}
	gid, err := sudoID("SUDO_GID")
	if err != nil {
		return 1, err
	}
	if err := checkOutputFDs(); err != nil {
		return 1, err
	}
	request, err := managedlaunch.DecodeRequest(os.Stdin)
	if err != nil {
		return 1, err
	}
	store, err := managedstore.Open(registry, int(uid))
	if err != nil {
		return 1, err
	}
	if err := store.Authenticate(request.Credential); err != nil {
		_ = store.Close()
		return 1, err
	}
	baseFD, err := unix.Open(anchorBase, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = store.Close()
		return 1, err
	}
	defer func() { _ = unix.Close(baseFD) }()
	groupsFD, err := openCgroupBase()
	if err != nil {
		_ = store.Close()
		return 1, err
	}
	defer func() { _ = unix.Close(groupsFD) }()
	slot, err := acquireLaunchSlot(baseFD, uid, 0, func(slot *launchSlot) error {
		return recoverSlot(baseFD, groupsFD, slot, 0, killCgroup)
	})
	if err != nil {
		_ = store.Close()
		return 1, err
	}
	defer func() { _ = slot.Close() }()
	snapshot, err := store.OpenPinnedSnapshot(request.Credential, request.ProjectID, request.Name, request.Revision)
	request.Credential = ""
	if err != nil {
		_ = store.Close()
		return 1, err
	}
	if err := store.Close(); err != nil {
		_ = snapshot.Close()
		return 1, err
	}
	defer func() { _ = snapshot.Close() }()
	engine, err := openTrustedEngine(managedlaunch.FixedEnginePath)
	if err != nil {
		return 1, err
	}
	defer func() { _ = engine.Close() }()
	parsed, err := config.ParseManagedProfileSnapshot(request.Name, snapshot.Profile)
	if err != nil {
		return 1, err
	}
	// Reject unsupported intent before privileged mount setup, independently of
	// path resolution that must take place inside the pinned mount view.
	if err := validateIntent(parsed.Profile()); err != nil {
		return 1, err
	}
	identity, err := session.ProcessIdentity(os.Getpid())
	if err != nil {
		return 1, err
	}
	journal, group, err := prepareSlot(baseFD, groupsFD, slot, identity, 0, killCgroup)
	if err != nil {
		return 1, fmt.Errorf("slot setup failed; slot quarantined: %w", err)
	}
	defer func() { _ = group.Close() }()
	// No caller-supplied descriptors survive either privileged watchdog exec or
	// the later unprivileged supervisor exec; only explicit handoff FDs are kept.
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return 1, err
	}
	watch, err := startWatchdog(slot, journal)
	if err != nil {
		return 1, fmt.Errorf("watchdog startup failed; slot quarantined: %w", err)
	}
	code, launchErr := launch(request, snapshot, engine, slot, group, watch, uid, gid, startup)
	cleanupErr := watch.finish()
	if cleanupErr != nil {
		// Reconcile only after the watchdog is reaped; otherwise it still owns
		// the shared flock and remains responsible for bounded cleanup.
		if watch.crashed {
			if err := recoverSlot(baseFD, groupsFD, slot, 0, killCgroup); err != nil {
				return 1, fmt.Errorf("watchdog and recovery failed; slot quarantined: %w", err)
			}
		}
		return 1, cleanupErr
	}
	return code, launchErr
}

func validateIntent(profile config.Profile) error {
	if len(profile.Network) != 0 {
		return errors.New("network intent is unsupported in this launcher")
	}
	for _, rule := range profile.Files {
		if filepath.IsAbs(rule.Path) || strings.HasPrefix(rule.Path, "~") || filepath.Clean(rule.Path) != rule.Path || len(rule.Access) != 1 || rule.Access[0] != "read" {
			return errors.New("only project-relative read intent is supported")
		}
	}
	return nil
}

func launch(request managedlaunch.Request, snapshot *managedstore.PinnedSnapshot, engine *os.File, slot *launchSlot, group *os.File, watch *watchdog, uid, gid uint32, startup *time.Timer) (int, error) {
	// Mount namespaces are per-thread. Every mount and child fork must remain on
	// this OS thread; never unlock it with the namespace still attached.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return 1, fmt.Errorf("private mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return 1, fmt.Errorf("private mount propagation: %w", err)
	}
	anchor := filepath.Join(anchorBase, anchorName(slot))
	project := filepath.Join(anchor, "project")
	policy := filepath.Join(anchor, "policy")
	work := filepath.Join(anchor, "work")
	for _, path := range []string{project, policy, work} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return 1, err
		}
	}
	if err := os.Chown(work, int(uid), int(gid)); err != nil {
		return 1, err
	}
	if err := os.Chmod(project, 0o755); err != nil { //nolint:gosec // root-owned mountpoint must be traversable after privilege drop
		return 1, err
	}
	if err := os.Chmod(policy, 0o755); err != nil { //nolint:gosec // root-owned mountpoint exposes only public policy intent
		return 1, err
	}
	if err := bindFD(snapshot.Project, project); err != nil {
		return 1, err
	}
	defer func() { _ = unix.Unmount(project, unix.MNT_DETACH) }()
	if err := bindFD(snapshot.Policy, policy); err != nil {
		return 1, err
	}
	defer func() { _ = unix.Unmount(policy, unix.MNT_DETACH) }()
	enginePath := filepath.Join(anchor, "engine")
	//nolint:gosec // fixed filename inside the verified root-controlled slot anchor
	engineTarget, err := os.OpenFile(enginePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 1, err
	}
	if err := engineTarget.Close(); err != nil {
		return 1, err
	}
	if err := bindEngineFD(engine, enginePath); err != nil {
		return 1, err
	}
	defer func() { _ = unix.Unmount(enginePath, unix.MNT_DETACH) }()
	publicSnapshot := filepath.Join(anchor, "selected.json")
	if err := os.WriteFile(publicSnapshot, snapshot.Profile, 0o444); err != nil { //nolint:gosec // reviewed profile is deliberately public read-only intent
		return 1, err
	}
	if err := os.Chmod(publicSnapshot, 0o444); err != nil { //nolint:gosec // exact public snapshot remains root-owned and read-only
		return 1, err
	}
	input := supervisorInput{ProjectID: request.ProjectID, Name: request.Name, Revision: request.Revision, Profile: snapshot.Profile, Engine: enginePath, Home: request.Home, ConfigHome: request.ConfigHome, Args: request.Args, Project: project, TemporaryRoot: work, SnapshotPath: publicSnapshot, RequirePIE: request.RequirePIE}
	data, err := json.Marshal(input)
	if err != nil || len(data) > managedlaunch.Limit {
		return 1, errors.New("invalid supervisor handoff")
	}
	if err := snapshot.Close(); err != nil {
		return 1, err
	}
	if err := engine.Close(); err != nil {
		return 1, err
	}
	// Do not inherit any descriptor supplied by sudo or the invoking process.
	// The exec machinery explicitly installs only stdin/stdout/stderr for the
	// unprivileged supervisor; newly created Go pipes are CLOEXEC as well.
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return 1, fmt.Errorf("close-on-exec descriptor isolation: %w", err)
	}
	if err := dropBoundingAndSetNNP(); err != nil {
		return 1, err
	}
	cmd := exec.Command(executable, "--supervise")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(group.Fd())}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + request.Home, "XDG_CONFIG_HOME=" + request.ConfigHome}
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if !startup.Stop() {
		return 1, errors.New("launch setup deadline exceeded")
	}
	select {
	case watchErr := <-watch.done:
		watch.crashed = true
		return 1, fmt.Errorf("watchdog exited before supervisor startup: %v", watchErr)
	default:
	}
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	select {
	case err = <-wait:
	case watchErr := <-watch.done:
		watch.crashed = true
		_ = killCgroup(int(group.Fd()), 5*time.Second)
		_ = cmd.Process.Kill()
		waitErr := <-wait
		err = errors.Join(fmt.Errorf("watchdog exited during launch: %v", watchErr), waitErr)
	}
	close(done)
	signal.Stop(signals)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 0 {
			return exit.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func bindFD(file *os.File, target string) error {
	if err := unix.Mount("/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10), target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	// The first supported subset never writes or executes from either mounted
	// object. Remount the bind itself, not the underlying shared filesystem.
	if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		_ = unix.Unmount(target, unix.MNT_DETACH)
		return err
	}
	return nil
}

func bindEngineFD(file *os.File, target string) error {
	if err := unix.Mount("/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10), target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		_ = unix.Unmount(target, unix.MNT_DETACH)
		return err
	}
	return nil
}

// openTrustedEngine verifies root-owned, non-writable ancestors and pins the
// verified static executable before any unprivileged version or engine exec.
func openTrustedEngine(path string) (*os.File, error) {
	if path != managedlaunch.FixedEnginePath {
		return nil, errors.New("unexpected engine path")
	}
	identity, err := trustedPath(path, true)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "trusted-engine")
	if err := validateEngineFD(file, identity, 0); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateEngineFD(file *os.File, identity unix.Stat_t, owner uint32) error {
	var opened unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil {
		return err
	}
	if opened.Dev != identity.Dev || opened.Ino != identity.Ino || opened.Uid != owner || opened.Mode&0o7022 != 0 || opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 || opened.Mode&0o111 == 0 || opened.Size <= 0 || opened.Size > 128*1024*1024 {
		return errors.New("trusted engine changed or is writable")
	}
	binary, err := elf.NewFile(file)
	if err != nil {
		return errors.New("trusted engine is not an ELF executable")
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("trusted engine must be statically linked")
		}
	}
	libraries, err := binary.ImportedLibraries()
	if err != nil || len(libraries) != 0 {
		return errors.New("trusted engine has dynamic dependencies")
	}
	return nil
}

func sudoID(name string) (uint32, error) {
	value := os.Getenv(name)
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return 0, errors.New("validated sudo caller identity required")
	}
	id, err := strconv.ParseUint(value, 10, 31)
	if err != nil || id == 0 {
		return 0, errors.New("validated sudo caller identity required")
	}
	return uint32(id), nil
}

// Only anonymous output pipes are accepted. The CLI copies their bytes to the
// requested destinations; arbitrary inherited regular/socket/authority FDs are
// not consumed by the root helper or propagated to the workload.
func checkOutputFDs() error {
	for _, fd := range []int{0, 1, 2} {
		if err := checkAnonymousPipe(fd); err != nil {
			return err
		}
	}
	return nil
}

func checkAnonymousPipe(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("launcher stdin, stdout and stderr must be anonymous pipes")
	}
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || !strings.HasPrefix(link, "pipe:[") || !strings.HasSuffix(link, "]") {
		return errors.New("launcher stdin, stdout and stderr must be anonymous pipes")
	}
	ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "pipe:["), "]"), 10, 64)
	if err != nil || ino != st.Ino {
		return errors.New("launcher pipe identity changed")
	}
	return nil
}

func trustedPath(path string, regular bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return st, err
	}
	defer func() { _ = unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 || !regular {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return st, err
		}
		_ = unix.Close(fd)
		fd = next
		if err := unix.Fstat(fd, &st); err != nil {
			return st, err
		}
		if st.Uid != 0 || st.Mode&0o022 != 0 {
			return st, errors.New("untrusted path ownership")
		}
	}
	if regular && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0o111 == 0) {
		return st, errors.New("invalid installed executable")
	}
	return st, nil
}

func verifyInstallation() error {
	path, err := os.Readlink("/proc/self/exe")
	if err != nil || path != executable {
		return errors.New("unexpected executable")
	}
	expected, err := trustedPath(executable, true)
	if err != nil {
		return err
	}
	var self unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &self); err != nil {
		return err
	}
	if self.Dev != expected.Dev || self.Ino != expected.Ino {
		return errors.New("executable changed")
	}
	if _, err := trustedPath(registry, false); err != nil {
		return err
	}
	st, err := trustedPath(anchorBase, false)
	if err != nil {
		return err
	}
	if st.Mode&0o7777 != 0o755 {
		return errors.New("launch anchor base must be mode 0755")
	}
	return nil
}

func dropBoundingAndSetNNP() error {
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		if cap == unix.CAP_SETPCAP {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_SETPCAP, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func supervise() (int, error) {
	if os.Getuid() <= 0 || os.Geteuid() != os.Getuid() || os.Getegid() != os.Getgid() {
		return 1, errors.New("supervisor must be unprivileged")
	}
	if err := checkDropped(); err != nil {
		return 1, err
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, managedlaunch.Limit+1))
	if err != nil || len(data) > managedlaunch.Limit {
		return 1, errors.New("invalid supervisor input")
	}
	var input supervisorInput
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return 1, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return 1, errors.New("trailing supervisor input")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(input.Name, input.Profile)
	if err != nil || snapshot.Revision() != input.Revision {
		return 1, errors.New("invalid selected snapshot")
	}
	resolved, err := managedlaunch.ReadOnlyProfile(snapshot, input.Project)
	if err != nil {
		return 1, err
	}
	_, _ = fmt.Fprintf(os.Stderr, "Selected managed project %s profile %s revision %s; snapshot %s; no network, no live approvals.\n", input.ProjectID, input.Name, input.Revision, input.SnapshotPath)
	for name, value := range map[string]string{"SYDGUARD_SELECTED_PROFILE": input.SnapshotPath, "SYDGUARD_PROJECT_ID": input.ProjectID, "SYDGUARD_PROFILE_NAME": input.Name, "SYDGUARD_PROFILE_REVISION": input.Revision} {
		if err := os.Setenv(name, value); err != nil {
			return 1, err
		}
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		return 1, err
	}
	defer func() { _ = null.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	options := syd.RunOptions{Engine: input.Engine, Directory: input.Project, Args: input.Args, Stdin: null, Stdout: os.Stdout, Stderr: os.Stderr, ResolvedProfile: &resolved, WorkTemporaryRoot: input.TemporaryRoot, RequirePIE: input.RequirePIE, StrictInputs: syd.TrustedRuntimeInputs{Read: []string{input.SnapshotPath}}, OnStrictRuntimeCapabilities: func(c syd.StrictRuntimeCapabilities) error {
		if len(c.Inputs.Read) != 1 || c.Inputs.Read[0] != input.SnapshotPath || len(c.Inputs.Exec)+len(c.IPCScopes) != 0 || c.Gateway != "" || c.TransitDNS != "" {
			return errors.New("unexpected strict runtime authority")
		}
		return nil
	}}
	return syd.Run(ctx, options)
}

func checkDropped() error {
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.New("supervisor supplementary groups not cleared")
	}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return errors.New("supervisor no-new-privileges missing")
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, field := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
		found := false
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, field) {
				found = true
				value := strings.TrimSpace(strings.TrimPrefix(line, field))
				if value != "0000000000000000" {
					return errors.New("supervisor capability set is not empty")
				}
				break
			}
		}
		if !found {
			return errors.New("supervisor capability status missing")
		}
	}
	return nil
}
