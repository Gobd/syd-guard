//go:build linux

package netns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Runtime owns only the resources successfully created for its topology.
type Runtime struct {
	Topology            Topology
	owned               Topology
	stateDir            string
	run                 runner
	mu                  sync.Mutex
	namespace, resolver uint64
	link                int
	table               uint64
}

type runner func(context.Context, Command) ([]byte, error)

func runCommand(ctx context.Context, c Command) ([]byte, error) {
	paths := map[string]string{"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft", "mkdir": "/usr/bin/mkdir", "install": "/usr/bin/install", "rm": "/usr/bin/rm"}
	path, ok := paths[c.Program]
	if !ok {
		return nil, fmt.Errorf("unsupported privileged operation")
	}
	args := append([]string{"-n", "--", path}, c.Args...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Once started, wait for the bounded kernel operation to finish. Killing sudo
	// on cancellation could leave an unrecorded successful privileged child.
	cmd := exec.Command("/usr/bin/sudo", args...) //nolint:gosec // commands are selected from fixed paths and built by validated topology operations
	cmd.Stdin = strings.NewReader(c.Input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %v: %w: %s", c.Program, c.Args, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Create installs an isolated resolver and the firewall before bringing up links.
// stateDir must be the common private controller authority for all allocations.
func Create(ctx context.Context, topology Topology, dnsPort, tcpPort uint16, stateDir string) (*Runtime, error) {
	return create(ctx, topology, dnsPort, tcpPort, stateDir, runCommand)
}

func create(ctx context.Context, topology Topology, dnsPort, tcpPort uint16, stateDir string, run runner) (*Runtime, error) {
	commands, err := topology.Prepare(dnsPort, tcpPort)
	if err != nil {
		return nil, err
	}
	stateDir, err = validateStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	lock, err := lockState(ctx, stateDir)
	if err != nil {
		return nil, err
	}
	defer unlockState(lock)
	r := &Runtime{Topology: topology, owned: topology, stateDir: stateDir, run: run}
	fail := func(e error) (*Runtime, error) {
		if cleanupErr := r.cleanup(); cleanupErr != nil {
			e = errors.Join(e, fmt.Errorf("rollback: %w", cleanupErr))
		}
		return nil, e
	}
	if err := checkPrefix(ctx, run, topology.Prefix); err != nil {
		return nil, err
	}
	if err := ensureResolverParent(ctx, run); err != nil {
		return nil, err
	}
	if _, err := rootDirectoryIdentity("/run"); err != nil {
		return nil, err
	}
	if _, err := os.Lstat("/run/netns"); err == nil {
		if _, err := rootDirectoryIdentity("/run/netns"); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	resolverDir := filepath.Join("/etc/netns", topology.Namespace)
	if _, err := run(ctx, Command{Program: "mkdir", Args: []string{"-m", "0755", "--", resolverDir}}); err != nil {
		return nil, err
	}
	r.resolver, err = rootDirectoryIdentity(resolverDir)
	if err != nil {
		return fail(fmt.Errorf("created resolver directory identity: %w", err))
	}
	f, err := os.CreateTemp(stateDir, ".resolver-")
	if err != nil {
		return fail(err)
	}
	source := f.Name()
	defer func() { _ = os.Remove(source) }()
	_, err = fmt.Fprintf(f, "nameserver %s\noptions attempts:1 timeout:1\n", topology.Host)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fail(err)
	}
	if _, err := run(ctx, Command{Program: "install", Args: []string{"-m", "0644", "--", source, filepath.Join(resolverDir, "resolv.conf")}}); err != nil {
		return fail(err)
	}
	for i, command := range commands {
		if _, err := run(ctx, command); err != nil {
			return fail(err)
		}
		switch i {
		case 0:
			r.namespace, err = namespaceIdentity(topology.Namespace)
		case 1:
			r.link, err = linkIdentity(topology.HostLink)
		case 5:
			// Identity recording must finish even if the caller cancels immediately
			// after the kernel transaction succeeded.
			r.table, err = tableIdentity(context.Background(), run, topology.Table)
		}
		if err != nil {
			return fail(fmt.Errorf("record created resource identity: %w", err))
		}
	}
	return r, nil
}

func (r *Runtime) UserExec(uid, gid int, argv []string) (Command, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.namespace == 0 {
		return Command{}, fmt.Errorf("namespace is closed")
	}
	id, err := namespaceIdentity(r.owned.Namespace)
	if err != nil || id != r.namespace {
		return Command{}, fmt.Errorf("namespace identity changed")
	}
	return r.owned.UserExec(uid, gid, argv)
}

// Close is retryable and never deletes an object whose identity has changed.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	lock, err := lockState(context.Background(), r.stateDir)
	if err != nil {
		return err
	}
	defer unlockState(lock)
	return r.cleanup()
}

func (r *Runtime) cleanup() error {
	ctx := context.Background()
	t := r.owned
	var errs []error
	// Keep the drop rules in place until our link has been removed.
	if r.link != 0 {
		id, err := linkIdentity(t.HostLink)
		if err != nil || id != r.link {
			errs = append(errs, fmt.Errorf("link identity changed or unavailable: %v", err))
		} else if _, err = r.run(ctx, Command{Program: "ip", Args: []string{"link", "del", t.HostLink}}); err != nil {
			errs = append(errs, err)
		} else {
			r.link = 0
		}
	}
	if r.table != 0 && r.link == 0 {
		id, err := tableIdentity(ctx, r.run, t.Table)
		if err != nil || id != r.table {
			errs = append(errs, fmt.Errorf("nft table identity changed or unavailable: %v", err))
		} else if _, err = r.run(ctx, Command{Program: "nft", Args: []string{"delete", "table", "inet", t.Table}}); err != nil {
			errs = append(errs, err)
		} else {
			r.table = 0
		}
	}
	if r.namespace != 0 {
		id, err := namespaceIdentity(t.Namespace)
		if err != nil || id != r.namespace {
			errs = append(errs, fmt.Errorf("namespace identity changed or unavailable: %v", err))
		} else if _, err = r.run(ctx, Command{Program: "ip", Args: []string{"netns", "del", t.Namespace}}); err != nil {
			errs = append(errs, err)
		} else {
			r.namespace = 0
		}
	}
	if r.resolver != 0 {
		dir := filepath.Join("/etc/netns", t.Namespace)
		id, err := rootDirectoryIdentity(dir)
		if err != nil || id != r.resolver {
			errs = append(errs, fmt.Errorf("resolver directory identity changed or unavailable: %v", err))
		} else if _, err = r.run(ctx, Command{Program: "rm", Args: []string{"-f", "--", filepath.Join(dir, "resolv.conf")}}); err != nil {
			errs = append(errs, err)
		} else if _, err = r.run(ctx, Command{Program: "rm", Args: []string{"-d", "--", dir}}); err != nil {
			errs = append(errs, err)
		} else {
			r.resolver = 0
		}
	}
	return errors.Join(errs...)
}

func rootDirectoryIdentity(path string) (uint64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return 0, fmt.Errorf("unsafe directory %s", path)
	}
	return st.Ino, nil
}

func ensureResolverParent(ctx context.Context, run runner) error {
	if _, err := rootDirectoryIdentity("/etc"); err != nil {
		return err
	}
	if _, err := os.Lstat("/etc/netns"); errors.Is(err, os.ErrNotExist) {
		if _, err := run(ctx, Command{Program: "mkdir", Args: []string{"-m", "0755", "--", "/etc/netns"}}); err != nil {
			// Another trusted creator may have won the exclusive mkdir.
			if _, statErr := rootDirectoryIdentity("/etc/netns"); statErr != nil {
				return errors.Join(err, statErr)
			}
		}
	} else if err != nil {
		return err
	}
	_, err := rootDirectoryIdentity("/etc/netns")
	return err
}

func namespaceIdentity(name string) (uint64, error) {
	if _, err := rootDirectoryIdentity("/run/netns"); err != nil {
		return 0, err
	}
	info, err := os.Lstat(filepath.Join("/run/netns", name))
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 {
		return 0, fmt.Errorf("unsafe namespace identity")
	}
	return st.Ino, nil
}

func linkIdentity(name string) (int, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return i.Index, nil
}

func tableIdentity(ctx context.Context, run runner, name string) (uint64, error) {
	out, err := run(ctx, Command{Program: "nft", Args: []string{"-j", "list", "table", "inet", name}})
	if err != nil {
		return 0, err
	}
	var result struct {
		Nftables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
				Handle uint64 `json:"handle"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return 0, err
	}
	for _, entry := range result.Nftables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == name && entry.Table.Handle != 0 {
			return entry.Table.Handle, nil
		}
	}
	return 0, fmt.Errorf("missing nft table handle")
}

func checkPrefix(ctx context.Context, run runner, prefix netip.Prefix) error {
	out, err := run(ctx, Command{Program: "ip", Args: []string{"-j", "-4", "route", "show", "table", "all"}})
	if err != nil {
		return err
	}
	var routes []struct {
		Dst string `json:"dst"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return fmt.Errorf("parse route inventory: %w", err)
	}
	for _, route := range routes {
		if route.Dst == "default" || route.Dst == "" {
			continue
		}
		p, err := netip.ParsePrefix(route.Dst)
		if err != nil {
			addr, e := netip.ParseAddr(route.Dst)
			if e != nil {
				return fmt.Errorf("unrecognized route destination %q", route.Dst)
			}
			p = netip.PrefixFrom(addr, 32)
		}
		if p.Overlaps(prefix) {
			return fmt.Errorf("transit prefix %s overlaps existing route %s", prefix, p)
		}
	}
	out, err = run(ctx, Command{Program: "ip", Args: []string{"-j", "-4", "address", "show"}})
	if err != nil {
		return err
	}
	var links []struct {
		Addresses []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return fmt.Errorf("parse address inventory: %w", err)
	}
	for _, link := range links {
		for _, address := range link.Addresses {
			ip, err := netip.ParseAddr(address.Local)
			if err != nil || !ip.Is4() || address.PrefixLen < 0 || address.PrefixLen > 32 {
				return fmt.Errorf("invalid address inventory entry %q/%d", address.Local, address.PrefixLen)
			}
			p := netip.PrefixFrom(ip, address.PrefixLen).Masked()
			if p.Overlaps(prefix) {
				return fmt.Errorf("transit prefix %s overlaps existing address prefix %s", prefix, p)
			}
		}
	}
	return nil
}

func validateStateDir(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("state directory must be an absolute clean path")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("unsafe state path %s", p)
		}
		if p == path {
			if int(st.Uid) != os.Geteuid() || info.Mode().Perm() != 0o700 {
				return "", fmt.Errorf("state directory must be owned and mode 0700")
			}
		} else if st.Uid != 0 && int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return "", fmt.Errorf("unsafe state ancestor %s", p)
		}
		if p == "/" {
			break
		}
	}
	return path, nil
}

func lockState(ctx context.Context, dir string) (*os.File, error) {
	if _, err := validateStateDir(dir); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(dir, ".netns.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "netns.lock")
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || int(st.Uid) != os.Geteuid() || info.Mode().Perm() != 0o600 || st.Nlink != 1 {
		_ = f.Close()
		return nil, fmt.Errorf("unsafe state lock")
	}
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			_ = f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func unlockState(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }
