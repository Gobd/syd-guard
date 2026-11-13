//go:build linux

package main

// Source-only composition. The caller retains the client through verified
// cgroup kill, reverse cleanup and release ACK. This does not install a
// watchdog dispatch or enable the selected launcher.
func newRootManagedNetworkAdapterWithWatchLease(baseFD, anchorFD, hostFD int, host networkObject, slot *launchSlot, j slotJournal, listeners *networkListeners, leaseSocket int, child *networkChild) (*managedNetworkAdapter, *networkWatchLeaseClient, error) {
	client, err := newRootNetworkWatchLeaseClient(leaseSocket, baseFD, slot, j, child)
	if err != nil {
		return nil, nil, err
	}
	adapter, err := newManagedNetworkAdapter(baseFD, anchorFD, hostFD, host, slot, 0, j, listeners, client.callbacks())
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return adapter, client, nil
}
