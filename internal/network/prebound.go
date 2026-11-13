package network

import "syscall"

// socketOpen checks only that Go still owns a live descriptor; it does not
// authenticate the underlying socket or its network namespace.
func socketOpen(socket syscall.Conn) bool {
	raw, err := socket.SyscallConn()
	if err != nil {
		return false
	}
	return raw.Control(func(uintptr) {}) == nil
}
