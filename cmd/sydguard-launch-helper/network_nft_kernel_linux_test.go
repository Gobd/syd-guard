//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Parent-controlled opt-in only. All tables live in one NEW anonymous network
// namespace: no host table, interface, forwarding setting, mount, or workload
// is changed. This proves kernel expression/ACK/handle acceptance, NOT traffic
// isolation, namespace leasing, crash cleanup, or selected launch readiness.
func TestManagedNFTIsolatedKernelAcceptance(t *testing.T) {
	if os.Getenv("SYDGUARD_TEST_ROOT_NFT_NAMESPACE") != "1" {
		t.Skip("requires explicit parent-owned isolated root fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("opt-in requires root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(original)
	var before unix.Stat_t
	if err := unix.Fstat(original, &before); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nsfd, ns, err := createAnonymousNetworkNamespace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(nsfd)
	if ns.Dev == before.Dev && ns.Ino == before.Ino {
		t.Fatal("fixture did not isolate network namespace")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	plan := managedFirewallPlan{journal: slotJournal{UID: 502, Index: 0, Nonce: hex.EncodeToString(nonce)}, dns: 34567, gateway: 45678}
	p := generatedNetworkPlan(plan.journal)
	// Each open/commit pair shares one five-second child budget; the outer
	// fixture budget is not a replacement for per-operation I/O bounds.
	commit := func() (networkObject, error) {
		operation, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		fd, pid, err := openManagedNFTSocket(operation, nsfd, ns)
		if err != nil {
			return networkObject{}, err
		}
		defer unix.Close(fd)
		return commitManagedFirewall(operation, nativeNFTWire{fd: fd}, pid, plan)
	}
	object, err := commit()
	if err != nil {
		t.Fatalf("actual isolated kernel commit: %v", err)
	}
	if object.Kind != "firewall" || object.Handle == 0 {
		t.Fatal("missing actual kernel identity")
	}
	t.Logf("isolated namespace dev=%d ino=%d table=%s handle=%d", ns.Dev, ns.Ino, p.Table, object.Handle)
	// Namespace destruction remains the final cleanup if any later assertion
	// fails. Do not delete a guessed name or touch the host's netfilter state.
	if got, err := lookupManagedNFT(ctx, nsfd, ns, p.Table); err != nil || got != object.Handle {
		t.Fatalf("actual GET: %d %v", got, err)
	}
	if err := deleteManagedNFT(ctx, nsfd, ns, p.Table, object.Handle+1); err == nil {
		t.Fatal("accepted changed handle")
	}
	if got, err := lookupManagedNFT(ctx, nsfd, ns, p.Table); err != nil || got != object.Handle {
		t.Fatalf("changed-handle attempt damaged table: %d %v", got, err)
	}
	_, duplicateErr := commit()
	if !errors.Is(duplicateErr, unix.EEXIST) {
		t.Fatalf("exclusive collision was not EEXIST: %v", duplicateErr)
	}
	if err := deleteManagedNFT(ctx, nsfd, ns, p.Table, object.Handle); err != nil {
		t.Fatalf("actual handle deletion: %v", err)
	}
	if _, err := lookupManagedNFT(ctx, nsfd, ns, p.Table); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("deleted table still visible or unexpected query error: %v", err)
	}
	current, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(current)
	if err := verifyNetworkNamespaceFD(current, networkObject{Kind: "namespace", Dev: before.Dev, Ino: before.Ino}); err != nil {
		t.Fatalf("caller namespace changed: %v", err)
	}
	t.Log("PASS isolated kernel expressions/all-ACK/GET/handle-only delete; caller namespace unchanged")
}
