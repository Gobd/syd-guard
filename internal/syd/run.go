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

type RunOptions struct {
	Engine         string
	Directory      string
	Args           []string
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	Gateway        string
	TransitDNS     string
	Scopes         []string
	ReadInputs     []string
	ExecInputs     []string
	OnReady        func(string, []string, []string) error
	OnNetworkReady func(string) error
	OnEvent        func([]byte) error
}

// Run is an initial immutable/no-network foreground launcher. It is not the
// future mutable controller, session registry or model-ready network workflow.
func Run(ctx context.Context, options RunOptions) (int, error) {
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
	profile, err := Profile(options.Directory, temporary, protected)
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
	if len(options.Scopes) > 0 {
		rules, scopes, err := LearningRules(options.Scopes, socket)
		if err != nil {
			return 2, err
		}
		for _, scope := range scopes {
			for _, blocked := range protected {
				if pathOverlaps(scope, blocked) {
					return 2, fmt.Errorf("filesystem ceiling overlaps protected authority: %s", scope)
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
	} else if options.TransitDNS != "" {
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
	if options.Gateway != "" {
		proxy := "http://" + options.Gateway
		command.Env = append(command.Env, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy, "http_proxy="+proxy, "https_proxy="+proxy, "all_proxy="+proxy, "NO_PROXY=", "no_proxy=")
	}
	command.Stdin, command.Stdout, command.Stderr = options.Stdin, options.Stdout, options.Stderr
	var logs, logWriter *os.File
	if options.OnEvent != nil {
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
