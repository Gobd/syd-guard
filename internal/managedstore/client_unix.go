//go:build linux || darwin

package managedstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

	"golang.org/x/sys/unix"
)

const helperPath = "/usr/local/libexec/sydguard-policy-helper"

// Client invokes only the installed helper via sudo; it never writes policy files.
// The credential directory must be outside all projects and inaccessible to workloads.
type Client struct{ credentialFile string }

// ErrIndeterminate means a mutation may have committed; authenticate a read and
// compare its SHA-256 revision before retrying. Registration needs admin inspection.
var ErrIndeterminate = errors.New("operation outcome indeterminate")

type ClientError struct{ Code, Message string }

func (e *ClientError) Is(target error) bool {
	return target == ErrIndeterminate && e.Code == "indeterminate"
}

func (e *ClientError) Error() string { return e.Message }

// CreateCredential exclusively creates a fresh credential in an existing private directory.
func CreateCredential(path string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("credential creation requires an unprivileged user")
	}
	dir, err := openPrivateDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dir) }()
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	name := filepath.Base(path)
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "credential")
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = unix.Unlinkat(dir, name, 0)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(token[:])); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	ok = true
	return nil
}

func openPrivateDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, errors.New("credential path must be absolute and clean")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if int(st.Uid) != os.Getuid() || st.Mode&0o7777 != 0o700 {
		_ = unix.Close(fd)
		return -1, errors.New("credential directory must be owned by the caller and mode 0700")
	}
	return fd, nil
}

func NewClient(credentialFile string) (*Client, error) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return nil, errors.New("client requires an unprivileged user")
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("managed policy helper is unsupported on this platform")
	}
	dir, err := openPrivateDirectory(credentialFile)
	if err != nil {
		return nil, err
	}
	_ = unix.Close(dir)
	return &Client{credentialFile: credentialFile}, nil
}

func (c *Client) credential() (string, error) {
	dir, err := openPrivateDirectory(c.credentialFile)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(dir) }()
	fd, err := unix.Openat(dir, filepath.Base(c.credentialFile), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "credential")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Getuid() || st.Nlink != 1 || st.Mode&0o7777 != 0o600 {
		return "", errors.New("invalid credential file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || len(data) != 64 {
		return "", errors.New("invalid credential file")
	}
	if _, err := hex.DecodeString(string(data)); err != nil {
		return "", errors.New("invalid credential file")
	}
	return string(data), nil
}

func (c *Client) call(ctx context.Context, request Request) (Response, error) {
	var response Response
	token, err := c.credential()
	if err != nil {
		return response, err
	}
	request.Credential = token
	data, err := json.Marshal(request)
	if err != nil || len(data) > 2*Limit+8192 {
		return response, errors.New("invalid or oversized helper request")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", helperPath)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.WaitDelay = 2 * time.Second
	var out boundedBuffer
	cmd.Stdout = &out
	runErr := cmd.Run()
	mutation := request.Operation != "read"
	transportError := func(message string) (Response, error) {
		if mutation {
			return Response{}, fmt.Errorf("%w: %s", ErrIndeterminate, message)
		}
		return Response{}, errors.New(message)
	}
	if ctx.Err() != nil {
		return transportError("helper deadline exceeded")
	}
	if out.overflow {
		return transportError("helper response too large")
	}
	response, err = decodeResponse(out.data, request.Operation)
	if err != nil {
		return transportError("helper unavailable or invalid response")
	}
	if response.Error != "" {
		return Response{}, &ClientError{Code: response.Code, Message: response.Error}
	}
	if runErr != nil {
		return transportError("helper failed")
	}
	if request.Operation != "register" {
		snapshot, err := config.ParseManagedProfileSnapshot(request.Name, response.Profile)
		if err != nil || snapshot.Revision() != response.Revision {
			return transportError("invalid helper snapshot")
		}
		// Return only the exact validated bytes, not a pathname to reopen.
		response.Profile = snapshot.Bytes()
	}
	return response, nil
}

type boundedBuffer struct {
	data     []byte
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 2*Limit+8192 {
		b.overflow = true
		return len(p), nil
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (c *Client) Register(ctx context.Context, canonicalProject string) (string, error) {
	r, err := c.call(ctx, Request{Operation: "register", Project: canonicalProject})
	return r.Project, err
}

func (c *Client) Create(ctx context.Context, projectID, name string) (Response, error) {
	return c.call(ctx, Request{Operation: "create", Project: projectID, Name: name})
}

func (c *Client) Read(ctx context.Context, projectID, name string) (Response, error) {
	return c.call(ctx, Request{Operation: "read", Project: projectID, Name: name})
}

func (c *Client) Replace(ctx context.Context, projectID, name, expected string, profile json.RawMessage) (Response, error) {
	return c.call(ctx, Request{Operation: "replace", Project: projectID, Name: name, Expected: expected, Profile: profile})
}

// ReconcileReplace performs an authenticated reread after an indeterminate
// replacement. The result describes current bytes, not whether a commit occurred;
// hashes can repeat and concurrent edits may occur after this read.
func (c *Client) ReconcileReplace(ctx context.Context, projectID, name, expected string, desired []byte) (Response, string, error) {
	if len(expected) != 64 {
		return Response{}, "", errors.New("invalid expected revision")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return Response{}, "", errors.New("invalid expected revision")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(name, desired)
	if err != nil {
		return Response{}, "", err
	}
	current, err := c.Read(ctx, projectID, name)
	if err != nil {
		return Response{}, "", err
	}
	switch {
	case current.Revision == expected && current.Revision == snapshot.Revision():
		return current, "matches_both", nil
	case current.Revision == snapshot.Revision():
		return current, "matches_desired", nil
	case current.Revision == expected:
		return current, "matches_expected", nil
	default:
		return current, "different", nil
	}
}
