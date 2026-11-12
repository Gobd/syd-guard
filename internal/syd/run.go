package syd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
)

// TrustedRuntimeInputs are separately authorized exact regular files. Execution
// grants also include read; these are not part of the resolved profile.
type TrustedRuntimeInputs struct {
	Read []string
	Exec []string
}

// HumanIPCApprovals establishes only ceilings, not automatic grants. The trusted
// controller must obtain per-run human approval for each exact IPC grant and
// enforce ceilings and protected paths on every grant. The caller must not use
// this facility with an automatic or untrusted controller.
type HumanIPCApprovals struct {
	Scopes []string
}

// StrictRuntimeCapabilities describes requested extra runtime authority for the
// parent integration to display and authorize alongside the reviewed profile.
// Paths are caller-supplied spellings, subsequently revalidated, not immutable
// filesystem identities. IPC ceilings include execution even though the current
// file-grant API does not grant execution.
type StrictRuntimeCapabilities struct {
	Inputs                 TrustedRuntimeInputs
	IPCScopes              []string
	IPCCeilingCapabilities []string
	Gateway                string
	TransitDNS             string
}

type RunOptions struct {
	Engine     string
	Directory  string
	Args       []string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	Gateway    string
	TransitDNS string
	Scopes     []string
	ReadInputs []string
	ExecInputs []string
	// RequirePIE opts back into upstream non-PIE rejection. Normal development
	// mode permits standard non-PIE toolchains without weakening path/net rules.
	RequirePIE bool
	// ResolvedProfile is caller-authorized, not proof of review or authorization.
	// Callers must synchronize ownership and not mutate it during Run's entry
	// copy. The strict capability callback, when invoked, signals the copy has
	// finished; otherwise wait until Run returns before mutating. Nil selects
	// legacy mode.
	ResolvedProfile *config.ResolvedProfile
	// Strict additions are separately authorized, and never inferred from the
	// legacy input or scope fields. The parent must display the effective policy
	// (profile + trusted runtime + per-run user approvals), not profile alone.
	StrictInputs TrustedRuntimeInputs
	// WorkTemporaryRoot is separately provisioned private strict scratch, not a project grant.
	WorkTemporaryRoot           string
	StrictIPC                   *HumanIPCApprovals
	OnStrictRuntimeCapabilities func(StrictRuntimeCapabilities) error
	OnReady                     func(string, []string, []string) error
	OnNetworkReady              func(string) error
	OnEvent                     func([]byte) error
	// Bootstrap is an explicit, permissive discovery launch. Its broad rules
	// are runtime-only and must never be saved as profile intent.
	Bootstrap bool
	// OnBootstrapStart receives the private temporary and protected paths before
	// execution, allowing the caller to configure exclusions for the log stream.
	OnBootstrapStart func(temporary string, protected []string) error
	// OnTrustedLog must drain the dedicated Syd descriptor to EOF. It must not
	// expose the descriptor to the workload or treat permission checks as I/O.
	OnTrustedLog func(io.Reader) error
	// OnExit reports the foreground Syd process signal, if any, after Wait.
	OnExit func(int, os.Signal)
}

// Run is an initial immutable/no-network foreground launcher. It is not the
// future mutable controller, session registry or model-ready network workflow.
func Run(ctx context.Context, options RunOptions) (int, error) {
	if options.Bootstrap {
		if options.ResolvedProfile != nil || len(options.Scopes) != 0 || options.OnEvent != nil || options.OnBootstrapStart == nil || options.OnTrustedLog == nil || options.Gateway != "" || options.TransitDNS != "" && options.OnNetworkReady == nil {
			return 2, fmt.Errorf("bootstrap requires a trusted log consumer, a network-ready callback for transparent networking, and no strict profile, scopes, event callback or proxy")
		}
		if err := strictReplayLandlockGate(); err != nil {
			return 2, err
		}
	} else if options.OnBootstrapStart != nil || options.OnTrustedLog != nil {
		return 2, fmt.Errorf("bootstrap callbacks require bootstrap mode")
	}
	// Copy before version execution or any asynchronous use. A caller writing
	// concurrently with this copy is still a data race and violates the API.
	if options.ResolvedProfile != nil {
		owned := cloneResolvedProfile(*options.ResolvedProfile)
		options.ResolvedProfile = &owned
		options.StrictInputs.Read = append([]string(nil), options.StrictInputs.Read...)
		options.StrictInputs.Exec = append([]string(nil), options.StrictInputs.Exec...)
		if options.StrictIPC != nil {
			ipc := *options.StrictIPC
			ipc.Scopes = append([]string(nil), ipc.Scopes...)
			options.StrictIPC = &ipc
		}
		if len(options.ReadInputs)+len(options.ExecInputs)+len(options.Scopes) != 0 {
			return 2, fmt.Errorf("strict replay rejects legacy inputs and scopes; use separately authorized strict inputs and human IPC approvals")
		}
		metadata := StrictRuntimeCapabilities{Inputs: options.StrictInputs, Gateway: options.Gateway, TransitDNS: options.TransitDNS}
		if options.StrictIPC != nil {
			metadata.IPCScopes = append([]string(nil), options.StrictIPC.Scopes...)
			metadata.IPCCeilingCapabilities = []string{"read", "readdir", "write", "create", "delete", "rename", "truncate", "mkdir", "rmdir", "symlink", "exec"}
		}
		// Detach metadata handed to the integration from the launch inputs.
		metadata.Inputs.Read = append([]string(nil), metadata.Inputs.Read...)
		metadata.Inputs.Exec = append([]string(nil), metadata.Inputs.Exec...)
		if len(metadata.Inputs.Read)+len(metadata.Inputs.Exec)+len(metadata.IPCScopes) > 0 || metadata.Gateway != "" || metadata.TransitDNS != "" {
			if options.OnStrictRuntimeCapabilities == nil {
				return 2, fmt.Errorf("strict runtime additions require a trusted effective-policy authorization callback")
			}
			if err := options.OnStrictRuntimeCapabilities(metadata); err != nil {
				return 2, fmt.Errorf("strict runtime additions not authorized: %w", err)
			}
		}
		options.ReadInputs, options.ExecInputs = options.StrictInputs.Read, options.StrictInputs.Exec
		if options.StrictIPC != nil {
			options.Scopes = options.StrictIPC.Scopes
			if len(options.Scopes) == 0 {
				return 2, fmt.Errorf("human IPC approvals require explicit scopes")
			}
		}
		if err := strictReplayLandlockGate(); err != nil {
			return 2, err
		}
	} else if len(options.StrictInputs.Read)+len(options.StrictInputs.Exec) > 0 || options.WorkTemporaryRoot != "" || options.StrictIPC != nil || options.OnStrictRuntimeCapabilities != nil {
		return 2, fmt.Errorf("strict runtime options require a resolved profile")
	}
	if runtime.GOOS != "linux" {
		return 2, fmt.Errorf("syd execution requires Linux")
	}
	if len(options.Args) == 0 {
		return 2, fmt.Errorf("missing command after --")
	}
	engine, err := exec.LookPath(options.Engine)
	if err != nil {
		return 1, err
	}
	engine, err = filepath.Abs(engine)
	if err != nil {
		return 1, err
	}
	engine, err = filepath.EvalSymlinks(engine)
	if err != nil {
		return 1, err
	}
	version, err := exec.CommandContext(ctx, engine, "--version").Output() //nolint:gosec // operator-selected engine and fixed diagnostic option
	if err != nil {
		return 1, err
	}
	if !strings.HasPrefix(string(version), "syd 3.59.0 ") {
		return 1, fmt.Errorf("foreground spike is validated only for Syd 3.59.0; found %s", strings.SplitN(string(version), "\n", 2)[0])
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return 1, err
	}
	stateRoot, err := config.StateDirectory()
	if err != nil {
		return 1, err
	}
	state := filepath.Join(stateRoot, "runs")
	if err := privateDirectory(state); err != nil {
		return 1, err
	}
	authority, err := os.MkdirTemp(state, "run-")
	if err != nil {
		return 1, err
	}
	defer func() { _ = os.RemoveAll(authority) }()
	workTemp := filepath.Join(home, ".cache", "sydguard-workloads")
	if options.WorkTemporaryRoot != "" {
		if !filepath.IsAbs(options.WorkTemporaryRoot) || filepath.Clean(options.WorkTemporaryRoot) != options.WorkTemporaryRoot {
			return 1, fmt.Errorf("strict temporary root must be absolute and clean")
		}
		workTemp = options.WorkTemporaryRoot
	}
	if err := privateDirectory(workTemp); err != nil {
		return 1, err
	}
	temporary, err := os.MkdirTemp(workTemp, "tmp-")
	if err != nil {
		return 1, err
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	configBase, err := os.UserConfigDir()
	if err != nil {
		return 1, err
	}
	protected := []string{filepath.Dir(state), filepath.Join(configBase, "sydguard"), engine}
	executable, err := os.Executable()
	if err != nil {
		return 1, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return 1, err
	}
	protected = append(protected, executable)
	if options.Bootstrap {
		// Discovery must not grant access to the fixed privileged helper or
		// its registry, even when those paths do not yet exist on this host.
		for _, path := range []string{"/usr/local/libexec/sydguard-policy-helper", "/usr/local/libexec/sydguard-policy-admin", "/var/lib/sydguard-policy", "/usr/bin/sudo"} {
			protected = append(protected, path)
			canonical, err := config.RevalidateResolvedFilePath(path)
			if err != nil {
				return 1, fmt.Errorf("cannot validate bootstrap authority exclusion: %w", err)
			}
			if canonical != path {
				protected = append(protected, canonical)
			}
		}
	}
	var profile string
	if options.ResolvedProfile == nil {
		profile, err = Profile(options.Directory, temporary, protected)
	} else {
		profile, err = StrictProfile(options.Directory, temporary, protected, *options.ResolvedProfile)
	}
	if err != nil {
		return 2, err
	}
	inputRules, err := InputRules(options.ReadInputs, options.ExecInputs, protected)
	if err != nil {
		return 2, err
	}
	profile += inputRules
	if options.Gateway != "" {
		rules, err := GatewayRules(options.Gateway)
		if err != nil {
			return 2, err
		}
		profile += rules
	}
	socket := filepath.Join(authority, "syd.sock")
	if options.TransitDNS != "" {
		rules, err := TransparentRules(options.TransitDNS)
		if err != nil {
			return 2, err
		}
		profile += rules
		resolver, err := filepath.EvalSymlinks("/etc/resolv.conf")
		if err != nil || literalPath(resolver) != nil {
			return 1, fmt.Errorf("invalid namespace resolver path")
		}
		profile += "allow/read,stat+" + resolver + "\nallow/lock/read+" + resolver + "\n"
	}
	switch {
	case options.Bootstrap:
		profile += bootstrapRules()
		if options.TransitDNS != "" {
			if err := literalPath(socket); err != nil {
				return 2, err
			}
			// Only synthetic destinations are admitted; the namespace firewall and
			// gateway still vet the actual public dial before any data is copied.
			profile += "allow/net/connect+tcp!198.18.0.0/15!*\nipc:" + socket + "\nlock:ipc\n"
		}
		if err := options.OnBootstrapStart(temporary, append([]string(nil), protected...)); err != nil {
			return 1, fmt.Errorf("bootstrap collector setup failed: %w", err)
		}
	case len(options.Scopes) > 0:
		rules, scopes, err := LearningRules(options.Scopes, socket)
		if err != nil {
			return 2, err
		}
		for _, scope := range scopes {
			for _, blocked := range protected {
				canonical, err := config.RevalidateResolvedFilePath(blocked)
				if err != nil || pathOverlaps(scope, canonical) {
					return 2, fmt.Errorf("filesystem ceiling overlaps or cannot validate protected authority; place engine, wrapper and state outside the ceiling")
				}
			}
		}
		if options.OnReady == nil || options.OnEvent == nil {
			return 2, fmt.Errorf("learning requires trusted controller callbacks")
		}
		if err := options.OnReady(socket, scopes, protected); err != nil {
			return 1, err
		}
		profile += rules
	case options.TransitDNS != "":
		return 2, fmt.Errorf("transparent networking requires trusted IPC and logging")
	}
	if options.TransitDNS != "" && options.OnNetworkReady == nil {
		return 2, fmt.Errorf("transparent networking requires a network-ready callback")
	}
	// Syd resolves matching rules by position. Keep immutable denies after all
	// generated input, network and IPC setup rules.
	preset, err := ProtectedRules(options.Directory, protected)
	if err != nil {
		return 2, err
	}
	profile += preset
	if options.RequirePIE {
		profile += "trace/allow_unsafe_exec_nopie:0\n"
	}
	if options.Bootstrap {
		paths := append(append([]string(nil), protected...), filepath.Join(options.Directory, ".sydguard"))
		profile += bootstrapAncestorRules(paths)
	}
	profilePath := filepath.Join(authority, "foreground.syd-3")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		return 1, err
	}
	argv := []string{"-P", profilePath, "--"}
	startFile := ""
	if options.TransitDNS != "" {
		// Start the real workload only after the controller has verified the live
		// socket. This fixed shell gate receives no control credentials or log FD.
		startFile = filepath.Join(temporary, "network-ready")
		argv = append(argv, "/bin/sh", "-c", `while [ ! -f "$1" ]; do /bin/sleep 0.02 || exit 1; done; shift; exec "$@"`, "sydguard-start", startFile)
	}
	argv = append(argv, options.Args...)
	command := exec.CommandContext(ctx, engine, argv...) //nolint:gosec // validated generated profile and operator argv; direct exec, no shell interpolation
	command.Dir = options.Directory
	command.Env = append(os.Environ(), "TMPDIR="+temporary)
	if options.WorkTemporaryRoot != "" {
		command.Env = append(command.Env, "SYDGUARD_TMPDIR="+temporary)
	}
	if options.Bootstrap {
		command.Env = append(command.Env, "SYD_LOG=warn")
	}
	if options.Gateway != "" {
		proxy := "http://" + options.Gateway
		command.Env = append(command.Env, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy, "http_proxy="+proxy, "https_proxy="+proxy, "all_proxy="+proxy, "NO_PROXY=", "no_proxy=")
	}
	command.Stdin, command.Stdout, command.Stderr = options.Stdin, options.Stdout, options.Stderr
	var logs, logWriter *os.File
	if options.OnEvent != nil || options.OnTrustedLog != nil {
		logs, logWriter, err = os.Pipe()
		if err != nil {
			return 1, err
		}
		defer func() { _ = logs.Close(); _ = logWriter.Close() }()
		command.ExtraFiles = []*os.File{logWriter}
		command.Env = append(command.Env, "SYD_LOG_FD=3")
	}
	if err := command.Start(); err != nil {
		return 1, err
	}
	var ready chan error
	if options.TransitDNS != "" {
		ready = make(chan error, 1)
		go func() {
			deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			for {
				if _, err := (IPC{Socket: socket}).Version(deadline); err == nil {
					if err := options.OnNetworkReady(socket); err != nil {
						ready <- err
					} else {
						ready <- os.WriteFile(startFile, nil, 0o600)
					}
					return
				}
				select {
				case <-deadline.Done():
					ready <- fmt.Errorf("syd IPC startup failed: %w", deadline.Err())
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		}()
	}
	var logged chan struct{}
	var logErr error
	if logs != nil {
		_ = logWriter.Close()
		logged = make(chan struct{})
		go func() {
			defer close(logged)
			if ready != nil {
				if err := <-ready; err != nil {
					logErr = err
					_ = command.Process.Kill()
					return
				}
			}
			if options.OnTrustedLog != nil {
				if err := options.OnTrustedLog(logs); err != nil {
					logErr = fmt.Errorf("trusted log delivery failed: %w", err)
					_ = command.Process.Kill()
				}
				return
			}
			scanner := bufio.NewScanner(logs)
			scanner.Buffer(make([]byte, 4096), 64*1024)
			for scanner.Scan() {
				if err := options.OnEvent(append([]byte(nil), scanner.Bytes()...)); err != nil {
					logErr = fmt.Errorf("trusted event delivery failed: %w", err)
					_ = command.Process.Kill()
					return
				}
			}
			if err := scanner.Err(); err != nil {
				logErr = fmt.Errorf("trusted Syd log failed: %w", err)
				_ = command.Process.Kill()
			}
		}()
	}
	waitErr := command.Wait()
	if options.OnExit != nil && command.ProcessState != nil {
		code := command.ProcessState.ExitCode()
		if code < 0 {
			code = 1
		}
		options.OnExit(code, processSignal(command.ProcessState))
	}
	if logged != nil {
		<-logged
		_ = logs.Close()
	}
	if logErr != nil {
		return 1, logErr
	}
	if err := waitErr; err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code := exit.ExitCode()
			if code < 0 {
				code = 1
			}
			return code, nil
		}
		return 1, err
	}
	return 0, nil
}

func cloneResolvedProfile(profile config.ResolvedProfile) config.ResolvedProfile {
	profile.Files = append([]config.FileRule(nil), profile.Files...)
	for i := range profile.Files {
		profile.Files[i].Access = append([]string(nil), profile.Files[i].Access...)
	}
	profile.Network = append([]config.NetworkRule(nil), profile.Network...)
	return profile
}

func pathOverlaps(a, b string) bool {
	within := func(path, root string) bool {
		rel, err := filepath.Rel(root, path)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return within(a, b) || within(b, a)
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("runtime state must be a private real directory: %s", path)
	}
	return nil
}
