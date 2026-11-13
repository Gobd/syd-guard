//go:build linux

package main

import (
	"context"

	"golang.org/x/sys/unix"
)

// All native operations are selected by the private production constructor.
// Tests may supply an independent per-adapter facade; there is no fallback.
type networkAdapterOps struct {
	createNamespace func(context.Context) (int, networkObject, error)
	createResolver  func(context.Context, *managedNetworkAdapter, networkPlan) (networkObject, error)
	installFirewall func(context.Context, int, *launchSlot, uint32, slotJournal, int, networkObject, *networkListeners) (networkObject, error)
	createVeth      func(context.Context, networkPlan, int, networkObject, int, networkObject) (networkObject, error)
	openRoute       func(context.Context, int, networkObject) (*managedRoute, error)
	collision       func(context.Context, networkPlan, int, networkObject) error
	lookupFirewall  func(context.Context, int, networkObject, string) (uint64, error)
	deleteFirewall  func(context.Context, int, networkObject, string, uint64) error
	deleteVeth      func(context.Context, networkPlan, networkObject, int, networkObject, int, networkObject) error
	hostCookie      func(context.Context, int, networkObject) (uint64, error)
}

func nativeNetworkAdapterOps() networkAdapterOps {
	return networkAdapterOps{createNamespace: createAnonymousNetworkNamespace, createResolver: func(ctx context.Context, a *managedNetworkAdapter, p networkPlan) (networkObject, error) {
		return a.createResolver(ctx, p)
	}, installFirewall: installManagedFirewall, createVeth: createManagedVeth, openRoute: managedRouteHandle, collision: checkNetworkCollisionInNamespace, lookupFirewall: lookupManagedNFT, deleteFirewall: deleteManagedNFT, deleteVeth: deleteManagedVeth, hostCookie: networkHostCookie}
}
func networkHostCookie(ctx context.Context, fd int, host networkObject) (uint64, error) {
	socket, _, err := openManagedNFTSocket(ctx, fd, host)
	if err != nil {
		return 0, err
	}
	defer unix.Close(socket)
	cookie, err := unix.GetsockoptUint64(socket, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, err
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	return cookie, nil
}
