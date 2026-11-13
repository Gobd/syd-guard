//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLiveSealedEnginePeerIdentity(t *testing.T) {
	if path := os.Getenv("SYDGUARD_TEST_SEALED_SERVER"); path != "" {
		_ = unix.Close(3)
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = os.Stdout.WriteString("ready\n")
		for i := 0; i < 2; i++ {
			conn, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			_, _ = conn.Read(b[:])
			_ = conn.Close()
		}
		return
	}
	if os.Getuid() == 0 {
		t.Skip("ordinary child test")
	}
	root, err := os.MkdirTemp("", "sgsealed-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socket := filepath.Join(root, "s")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	fd, err := unix.MemfdCreate("peer-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	sealed := os.NewFile(uintptr(fd), "peer-test")
	defer sealed.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(sealed, h), original); err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if _, err = sealed.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err = unix.FcntlInt(sealed.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestLiveSealedEnginePeerIdentity$") //nolint:gosec // sealed owned test program
	cmd.ExtraFiles = []*os.File{sealed}
	cmd.Env = append(os.Environ(), "SYDGUARD_TEST_SEALED_SERVER="+socket)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("peer startup %q %v", line, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runtime, err := pinLiveRuntimeDigest(ctx, cmd.Process, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	dfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(dfd), "dir")
	defer dir.Close()
	sfd, err := unix.Open(socket, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	node := os.NewFile(uintptr(sfd), "socket")
	defer node.Close()
	endpoint := &liveEngineEndpoint{dir: dir, socket: node, serverUID: uint32(os.Getuid()), socketOwner: uint32(os.Getuid()), runtime: runtime}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := endpoint.verifyPeer(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := endpoint.verifyPeer(conn); err != nil {
		t.Fatalf("second connection identity: %v", err)
	}
	runtime.ino++
	if err := endpoint.verifyPeer(conn); err == nil {
		t.Fatal("changed runtime inode accepted")
	}
	runtime.ino--
	if err := os.Rename(socket, socket+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.verifyPeer(conn); err == nil {
		t.Fatal("renamed socket accepted")
	}
	_ = conn.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
	if err := runtime.verify(); err == nil {
		t.Fatal("exited peer accepted")
	}
}

func TestLiveRuntimeSealedProcessIdentity(t *testing.T) {
	if os.Getenv("SYDGUARD_TEST_SEALED_CHILD") == "1" {
		_ = unix.Close(3)
		_, _ = os.Stdout.WriteString("ready\n")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		return
	}
	if os.Getuid() == 0 {
		t.Skip("ordinary child test")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	info, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.MemfdCreate("identity-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	sealed := os.NewFile(uintptr(fd), "identity-test")
	defer sealed.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(sealed, h), original); err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if _, err := sealed.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyLiveSealedExecutable(sealed, digest); err == nil {
		t.Fatal("unsealed executable accepted")
	}
	required := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	for _, missing := range []int{unix.F_SEAL_WRITE, unix.F_SEAL_GROW, unix.F_SEAL_SHRINK, unix.F_SEAL_SEAL} {
		fd, err := unix.MemfdCreate("missing-seal", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), "missing-seal")
		if _, err := io.Copy(f, io.NewSectionReader(original, 0, info.Size())); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, required&^missing); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyLiveSealedExecutable(f, digest); err == nil {
			t.Fatalf("missing seal %#x accepted", missing)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := unix.FcntlInt(sealed.Fd(), unix.F_ADD_SEALS, required); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyLiveSealedExecutable(sealed, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, err := verifyLiveSealedExecutable(sealed, digest); err != nil {
		t.Fatal(err)
	}
	offset, err := sealed.Seek(0, io.SeekCurrent)
	if err != nil || offset != 0 {
		t.Fatalf("hash moved offset: %d %v", offset, err)
	}
	cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestLiveRuntimeSealedProcessIdentity$") //nolint:gosec // owned sealed self-test executable
	cmd.ExtraFiles = []*os.File{sealed}
	cmd.Env = append(os.Environ(), "SYDGUARD_TEST_SEALED_CHILD=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = in.Close()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("child startup %q %v", line, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, err := pinLiveRuntimeDigest(ctx, cmd.Process, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.verify(); err != nil {
		t.Fatal(err)
	}
	var current unix.Stat_t
	if err := unix.Fstat(int(p.executable.Fd()), &current); err != nil {
		t.Fatal(err)
	}
	if int64(current.Size) != info.Size() {
		t.Fatal("runtime executable size changed")
	}
	var nilAuthority *liveRuntimeIdentity
	_, nilExecutableErr := verifyLiveSealedExecutable(nil, digest)
	if nilAuthority.verify() == nil || nilAuthority.Close() == nil || nilExecutableErr == nil {
		t.Fatal("nil authority accepted")
	}
	pidfd, err := unix.FcntlInt(p.pidfd.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	exefd, err := unix.FcntlInt(p.executable.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(pidfd)
		t.Fatal(err)
	}
	duplicate := &liveRuntimeIdentity{pid: p.pid, start: p.start, pidfd: os.NewFile(uintptr(pidfd), "dup-pidfd"), executable: os.NewFile(uintptr(exefd), "dup-exe"), dev: p.dev, ino: p.ino}
	if err := duplicate.verify(); err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}
	if duplicate.verify() == nil || duplicate.Close() == nil {
		t.Fatal("closed duplicate accepted")
	}
	if err := p.verify(); err != nil {
		t.Fatalf("closing duplicate affected original: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	if err := p.verify(); err == nil {
		t.Fatal("exited engine accepted")
	}
}
