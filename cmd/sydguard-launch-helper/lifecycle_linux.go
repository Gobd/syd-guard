//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const cgroupBase = "/sys/fs/cgroup/sydguard-launch"

// A preparing journal precedes resource creation. A complete ready journal
// binds both root-controlled object identities before any workload can fork.
type slotJournal struct {
	Version        int    `json:"version"`
	UID            uint32 `json:"uid"`
	Index          int    `json:"index"`
	Nonce          string `json:"nonce"`
	ParentPID      int    `json:"parent_pid"`
	ParentIdentity string `json:"parent_identity"`
	Phase          string `json:"phase"`
	AnchorDev      uint64 `json:"anchor_dev"`
	AnchorIno      uint64 `json:"anchor_ino"`
	CgroupDev      uint64 `json:"cgroup_dev"`
	CgroupIno      uint64 `json:"cgroup_ino"`
}

func anchorName(slot *launchSlot) string      { return slotName(slot.UID, slot.Index) + ".anchor" }
func journalName(slot *launchSlot) string     { return slotName(slot.UID, slot.Index) + ".journal" }
func journalTempName(slot *launchSlot) string { return journalName(slot) + ".pending" }

func newJournal(slot *launchSlot, identity string) (slotJournal, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return slotJournal{}, err
	}
	return slotJournal{Version: 1, UID: slot.UID, Index: slot.Index, Nonce: hex.EncodeToString(nonce[:]), ParentPID: os.Getpid(), ParentIdentity: identity, Phase: "preparing"}, nil
}

func validateJournal(slot *launchSlot, j slotJournal) error {
	if j.Version != 1 || j.UID != slot.UID || j.Index != slot.Index || j.ParentPID <= 0 || j.ParentIdentity == "" || len(j.ParentIdentity) > 128 {
		return errors.New("invalid slot journal binding")
	}
	nonce, err := hex.DecodeString(j.Nonce)
	if err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != j.Nonce {
		return errors.New("invalid slot journal nonce")
	}
	switch j.Phase {
	case "preparing":
		if j.AnchorDev != 0 || j.AnchorIno != 0 || j.CgroupDev != 0 || j.CgroupIno != 0 {
			return errors.New("invalid preparing journal")
		}
	case "ready":
		if j.AnchorIno == 0 || j.CgroupIno == 0 {
			return errors.New("invalid ready journal")
		}
	default:
		return errors.New("unknown slot journal phase")
	}
	return nil
}

// writeJournal only replaces the helper-owned journal while the slot flock is
// held. A pre-existing partial temp file is never overwritten or removed.
func writeJournal(baseFD int, slot *launchSlot, j slotJournal, create bool) error {
	if err := validateJournal(slot, j); err != nil {
		return err
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(baseFD, journalTempName(slot), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "slot-journal")
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if create {
		err = unix.Renameat2(baseFD, journalTempName(slot), baseFD, journalName(slot), unix.RENAME_NOREPLACE)
	} else {
		err = unix.Renameat(baseFD, journalTempName(slot), baseFD, journalName(slot))
	}
	if err != nil {
		return err
	}
	return unix.Fsync(baseFD)
}

func readJournal(baseFD int, slot *launchSlot, owner uint32) (slotJournal, bool, error) {
	var j slotJournal
	var stat unix.Stat_t
	err := unix.Fstatat(baseFD, journalTempName(slot), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return j, false, errors.New("partial slot journal quarantined")
	}
	if !errors.Is(err, unix.ENOENT) {
		return j, false, err
	}
	fd, err := unix.Openat(baseFD, journalName(slot), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return j, false, nil
	}
	if err != nil {
		return j, false, err
	}
	file := os.NewFile(uintptr(fd), "slot-journal")
	defer func() { _ = file.Close() }()
	if err := unix.Fstat(fd, &stat); err != nil {
		return j, false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != owner || stat.Nlink != 1 || stat.Size > 4096 {
		return j, false, errors.New("unsafe slot journal")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return j, false, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&j); err != nil || d.Decode(new(any)) != io.EOF {
		return j, false, errors.New("invalid slot journal")
	}
	canonical, err := json.Marshal(j)
	if err != nil || !bytes.Equal(data, canonical) || validateJournal(slot, j) != nil {
		return j, false, errors.New("noncanonical slot journal")
	}
	return j, true, nil
}

func openCheckedDirectory(parent int, name string, dev, ino uint64, owner uint32) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if st.Dev != dev || st.Ino != ino || st.Uid != owner || st.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("resource directory identity changed")
	}
	return fd, nil
}

func objectExists(parent int, name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

// killCgroup writes only the fixed cgroup.kill file and waits a finite interval
// for the kernel's subtree-wide populated=0 indication.
func killCgroup(fd int, timeout time.Duration) error {
	kill, err := unix.Openat(fd, "cgroup.kill", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cgroup kill unavailable: %w", err)
	}
	_, err = unix.Write(kill, []byte("1\n"))
	closeErr := unix.Close(kill)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	deadline := time.Now().Add(timeout)
	for {
		events, err := unix.Openat(fd, "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(events), "cgroup-events")
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(data) > 4096 {
			return errors.New("invalid cgroup events")
		}
		populated := -1
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "populated" {
				if len(fields) != 2 || populated != -1 {
					return errors.New("duplicate cgroup populated state")
				}
				populated, err = strconv.Atoi(fields[1])
				if err != nil || populated < 0 || populated > 1 {
					return errors.New("invalid cgroup populated state")
				}
			}
		}
		if populated == 0 {
			return nil
		}
		if populated != 1 || time.Now().After(deadline) {
			return errors.New("cgroup did not become empty")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// cleanupSlot never traverses the user-owned work directory. Nonempty or
// unverified resources retain their journal and quarantine the bounded slot.
func cleanupSlot(baseFD, cgroupFD int, slot *launchSlot, j slotJournal, owner uint32, kill func(int, time.Duration) error) error {
	if err := validateJournal(slot, j); err != nil || j.Phase != "ready" {
		return errors.New("slot is not recoverable")
	}
	name := slotName(slot.UID, slot.Index)
	anchor := anchorName(slot)
	anchorExists, err := objectExists(baseFD, anchor)
	if err != nil {
		return err
	}
	groupExists, err := objectExists(cgroupFD, name)
	if err != nil {
		return err
	}
	if !groupExists && anchorExists {
		return errors.New("missing cgroup for existing anchor")
	}
	if groupExists {
		fd, err := openCheckedDirectory(cgroupFD, name, j.CgroupDev, j.CgroupIno, owner)
		if err != nil {
			return err
		}
		err = kill(fd, 5*time.Second)
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	if anchorExists {
		fd, err := openCheckedDirectory(baseFD, anchor, j.AnchorDev, j.AnchorIno, owner)
		if err != nil {
			return err
		}
		for _, child := range []string{"selected.json", "engine"} {
			if err := unix.Unlinkat(fd, child, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				_ = unix.Close(fd)
				return err
			}
		}
		for _, child := range []string{"project", "policy", "work"} {
			if err := unix.Unlinkat(fd, child, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
				_ = unix.Close(fd)
				return err
			}
		}
		_ = unix.Close(fd)
		// Recheck the parent entry before removing the root-owned anchor.
		check, err := openCheckedDirectory(baseFD, anchor, j.AnchorDev, j.AnchorIno, owner)
		if err != nil {
			return err
		}
		_ = unix.Close(check)
		if err := unix.Unlinkat(baseFD, anchor, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	if groupExists {
		check, err := openCheckedDirectory(cgroupFD, name, j.CgroupDev, j.CgroupIno, owner)
		if err != nil {
			return err
		}
		_ = unix.Close(check)
		if err := unix.Unlinkat(cgroupFD, name, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(baseFD, journalName(slot), 0); err != nil {
		return err
	}
	return unix.Fsync(baseFD)
}

func recoverSlot(baseFD, cgroupFD int, slot *launchSlot, owner uint32, kill func(int, time.Duration) error) error {
	j, exists, err := readJournal(baseFD, slot, owner)
	if err != nil {
		return err
	}
	name := slotName(slot.UID, slot.Index)
	if !exists {
		a, err := objectExists(baseFD, anchorName(slot))
		if err != nil {
			return err
		}
		g, err := objectExists(cgroupFD, name)
		if err != nil {
			return err
		}
		if a || g {
			return errors.New("unrecorded slot resources quarantined")
		}
		return nil
	}
	if j.Phase != "ready" {
		return errors.New("incomplete slot journal quarantined")
	}
	return cleanupSlot(baseFD, cgroupFD, slot, j, owner, kill)
}
