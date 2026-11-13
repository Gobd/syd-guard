//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"
)

// networkPlan is reconstructed from the root-owned slot journal, never a
// request, controller registration, pathname, or process supplied by a caller.
type networkPlan struct {
	Namespace, HostLink, PeerLink, Table string
	Host, Agent                          netip.Addr
	HostMAC, PeerMAC                     string
}

type networkObject struct {
	Kind      string `json:"kind"`
	Dev       uint64 `json:"dev"`
	Ino       uint64 `json:"ino"`
	Handle    uint64 `json:"handle"`
	HostIndex int    `json:"host_index"`
	PeerIndex int    `json:"peer_index"`
	HostMAC   string `json:"host_mac"`
	PeerMAC   string `json:"peer_mac"`
}

type networkJournal struct {
	State   string          `json:"state"`
	Objects []networkObject `json:"objects"`
}

var networkKinds = [...]string{"namespace", "resolver", "firewall", "veth"}

func generatedNetworkPlan(j slotJournal) networkPlan {
	sum := sha256.Sum256([]byte(fmt.Sprintf("sydguard-network-v1:%d:%d:%s", j.UID, j.Index, j.Nonce)))
	id := hex.EncodeToString(sum[:6])
	base := sum[7] & 0xfc
	mac1 := [6]byte{0x02, sum[8], sum[9], sum[10], sum[11], sum[12]}
	mac2 := mac1
	mac2[5] ^= 1
	return networkPlan{
		Namespace: "sg-" + id, HostLink: "sgh" + id, PeerLink: "sga" + id, Table: "sg_" + id,
		Host: netip.AddrFrom4([4]byte{10, 232, sum[6], base + 1}), Agent: netip.AddrFrom4([4]byte{10, 232, sum[6], base + 2}),
		HostMAC: hex.EncodeToString(mac1[:]), PeerMAC: hex.EncodeToString(mac2[:]),
	}
}

func validNetworkObject(o networkObject, kind string, p networkPlan) bool {
	if o.Kind != kind {
		return false
	}
	switch kind {
	case "namespace", "resolver":
		return o.Dev != 0 && o.Ino != 0 && o.Handle == 0 && o.HostIndex == 0 && o.PeerIndex == 0 && o.HostMAC == "" && o.PeerMAC == ""
	case "firewall":
		return o.Dev == 0 && o.Ino == 0 && o.Handle != 0 && o.HostIndex == 0 && o.PeerIndex == 0 && o.HostMAC == "" && o.PeerMAC == ""
	case "veth":
		return o.Dev == 0 && o.Ino == 0 && o.Handle == 0 && o.HostIndex > 0 && o.PeerIndex > 0 && o.HostMAC == p.HostMAC && o.PeerMAC == p.PeerMAC
	}
	return false
}

func validateNetworkJournal(j slotJournal) error {
	n := j.Network
	if j.Phase != "ready" || n == nil || n.Objects == nil || len(n.Objects) > len(networkKinds) {
		return errors.New("invalid network journal")
	}
	p := generatedNetworkPlan(j)
	for i, o := range n.Objects {
		if !validNetworkObject(o, networkKinds[i], p) {
			return errors.New("invalid network resource identity")
		}
		for _, previous := range n.Objects[:i] {
			if o.Dev != 0 && o.Dev == previous.Dev && o.Ino == previous.Ino {
				return errors.New("duplicate network inode identity")
			}
		}
	}
	switch n.State {
	case "recorded":
	case "creating":
		if len(n.Objects) == len(networkKinds) {
			return errors.New("invalid network creating phase")
		}
	case "deleting":
		if len(n.Objects) == 0 {
			return errors.New("invalid network deleting phase")
		}
	case "activating", "active":
		if len(n.Objects) != len(networkKinds) {
			return errors.New("invalid network activation phase")
		}
	default:
		return errors.New("unknown network journal phase")
	}
	return nil
}

// An adapter must create exclusively, reject address/name collisions, verify
// kernel identity before deletion, and keep deny filtering until link removal.
type networkResourceAdapter interface {
	Create(context.Context, networkPlan, string) (networkObject, error)
	Activate(context.Context, networkPlan, []networkObject) error
	RemoveIfIdentityMatches(context.Context, networkPlan, networkObject) error
}

// lockNetworkLifecycle does not leave a goroutine waiting after cancellation.
// Callers start their transaction deadline before invoking it.
func lockNetworkLifecycle(ctx context.Context, slot *launchSlot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if slot.lifecycleMu.TryLock() {
			if err := ctx.Err(); err != nil {
				slot.lifecycleMu.Unlock()
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
}

// prepareNetwork persists a pending phase before each side effect. An error or
// crash in a pending phase quarantines the slot, including any prior objects.
func prepareNetwork(ctx context.Context, baseFD int, slot *launchSlot, owner uint32, j *slotJournal, a networkResourceAdapter) error {
	if slot == nil {
		return errors.New("missing launch slot")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := lockNetworkLifecycle(ctx, slot); err != nil {
		return err
	}
	defer slot.lifecycleMu.Unlock()
	if a == nil || j == nil || validateJournal(slot, *j) != nil || j.Phase != "ready" || j.Network != nil {
		return errors.New("network setup is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, exists, err := readJournal(baseFD, slot, owner)
	if err != nil || !exists || !reflect.DeepEqual(current, *j) {
		return errors.New("network setup journal is stale or unavailable")
	}
	j.Network = &networkJournal{State: "recorded", Objects: []networkObject{}}
	if err := writeJournal(baseFD, slot, *j, false); err != nil {
		return err
	}
	p := generatedNetworkPlan(*j)
	for _, kind := range networkKinds {
		if err := ctx.Err(); err != nil {
			return err
		}
		j.Network.State = "creating"
		if err := writeJournal(baseFD, slot, *j, false); err != nil {
			return err
		}
		object, err := a.Create(ctx, p, kind)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !validNetworkObject(object, kind, p) {
			return errors.New("created network resource has invalid identity")
		}
		j.Network.Objects = append(j.Network.Objects, object)
		j.Network.State = "recorded"
		if err := writeJournal(baseFD, slot, *j, false); err != nil {
			return err
		}
		if kind == "namespace" {
			if lease, ok := a.(interface {
				namespaceRecorded(context.Context, networkObject) error
			}); ok {
				if err := lease.namespaceRecorded(ctx, object); err != nil {
					return err
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.Network.State = "activating"
	if err := writeJournal(baseFD, slot, *j, false); err != nil {
		return err
	}
	if err := a.Activate(ctx, p, append([]networkObject(nil), j.Network.Objects...)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.Network.State = "active"
	if err := writeJournal(baseFD, slot, *j, false); err != nil {
		return err
	}
	return ctx.Err()
}

// Called only after a successfully verified cgroup kill. Unknown/pending
// creation and ambiguous activation are never cleaned up by name.
func cleanupNetwork(baseFD int, slot *launchSlot, j *slotJournal, a networkResourceAdapter) error {
	if a == nil {
		return errors.New("no authenticated network cleanup adapter")
	}
	if err := validateJournal(slot, *j); err != nil {
		return err
	}
	if j.Network.State != "recorded" && j.Network.State != "active" {
		return errors.New("ambiguous network resource phase")
	}
	p := generatedNetworkPlan(*j)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for len(j.Network.Objects) != 0 {
		i := len(j.Network.Objects) - 1
		object := j.Network.Objects[i]
		if err := ctx.Err(); err != nil {
			return err
		}
		j.Network.State = "deleting"
		if err := writeJournal(baseFD, slot, *j, false); err != nil {
			return err
		}
		if err := a.RemoveIfIdentityMatches(ctx, p, object); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		j.Network.Objects = j.Network.Objects[:i]
		j.Network.State = "recorded"
		if err := writeJournal(baseFD, slot, *j, false); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.Network = nil
	if err := writeJournal(baseFD, slot, *j, false); err != nil {
		return err
	}
	return ctx.Err()
}
