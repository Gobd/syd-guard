package network

import (
	"fmt"
	"net/netip"
	"sync"
)

// Synthetic holds a session-local, never-reassigned hostname/address mapping.
// Real upstream IPs are resolved only by the protected forwarding gateway.
type Synthetic struct {
	mu        sync.Mutex
	count     uint32
	allocator *SyntheticAllocator
	byHost    map[string]netip.Addr
	byIP      map[netip.Addr]string
}

// SyntheticAllocator never reuses an address during a controller lifetime, so
// a denial record from an ended or different session cannot name another map.
type SyntheticAllocator struct {
	mu   sync.Mutex
	next uint32
}

func NewSyntheticAllocator() *SyntheticAllocator { return &SyntheticAllocator{next: 1} }
func NewSynthetic() *Synthetic                   { return NewSyntheticWithAllocator(NewSyntheticAllocator()) }

func NewSyntheticWithAllocator(allocator *SyntheticAllocator) *Synthetic {
	return &Synthetic{allocator: allocator, byHost: map[string]netip.Addr{}, byIP: map[netip.Addr]string{}}
}

func (a *SyntheticAllocator) allocate() (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next >= 131071 {
		return netip.Addr{}, fmt.Errorf("controller synthetic address pool exhausted")
	}
	n := a.next
	a.next++
	return netip.AddrFrom4([4]byte{198, 18 + byte(n>>16), byte((n >> 8) & 0xff), byte(n & 0xff)}), nil
}

func (s *Synthetic) Address(host string) (netip.Addr, error) {
	target, err := Canonical(host, 443)
	if err != nil {
		return netip.Addr{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, ok := s.byHost[target.Host]; ok {
		return value, nil
	}
	if s.count >= 65534 {
		return netip.Addr{}, fmt.Errorf("session DNS mapping limit reached")
	}
	value, err := s.allocator.allocate()
	if err != nil {
		return netip.Addr{}, err
	}
	s.count++
	s.byHost[target.Host] = value
	s.byIP[value] = target.Host
	return value, nil
}

func (s *Synthetic) Host(address netip.Addr) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.byIP[address.Unmap()]
	return value, ok
}

// ExistingAddress never allocates a mapping during an approval.
func (s *Synthetic) ExistingAddress(host string) (netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	address, ok := s.byHost[host]
	return address, ok
}
