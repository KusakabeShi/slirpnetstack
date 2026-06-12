package slirpnetstack

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// localAddrs is the set of addresses assigned to the gateway. The stack runs
// with spoofing enabled (required so it can reply *as* arbitrary destination
// IPs for transparent forwarding), which as a side effect makes it proxy-answer
// ARP/NDP for any address. localAddrs lets us restore real-host behaviour on
// the L2 segment: only answer for ourselves. See hostFilterEndpoint.
type localAddrs struct {
	mu sync.RWMutex
	m  map[tcpip.Address]struct{}
}

func newLocalAddrs(addrs ...tcpip.Address) *localAddrs {
	l := &localAddrs{m: make(map[tcpip.Address]struct{}, len(addrs))}
	for _, a := range addrs {
		l.add(a)
	}
	return l
}

func (l *localAddrs) add(a tcpip.Address) {
	if a.Len() == 0 {
		return
	}
	l.mu.Lock()
	l.m[a] = struct{}{}
	l.mu.Unlock()
}

func (l *localAddrs) has(a tcpip.Address) bool {
	l.mu.RLock()
	_, ok := l.m[a]
	l.mu.RUnlock()
	return ok
}

// hostFilterEndpoint is a LinkEndpoint shim that makes the gateway behave like a
// real host on the L2 segment. Inbound ARP requests and IPv6 Neighbor
// Solicitations are only passed up to the stack when their target is one of our
// own addresses; otherwise they are dropped so the (spoofing) stack does not
// proxy-answer for addresses it doesn't own. Everything else - ARP/NA replies,
// TCP/UDP, and all outbound traffic - passes through untouched, so transparent
// forwarding keeps working.
type hostFilterEndpoint struct {
	nested.Endpoint
	local *localAddrs
}

func newHostFilter(lower stack.LinkEndpoint, local *localAddrs) *hostFilterEndpoint {
	e := &hostFilterEndpoint{local: local}
	e.Endpoint.Init(lower, e)
	return e
}

// DeliverNetworkPacket intercepts inbound frames before the stack sees them.
func (e *hostFilterEndpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if e.dropInbound(protocol, pkt) {
		return
	}
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}

// dropInbound reports whether an inbound packet should be dropped: an ARP
// request or IPv6 Neighbor Solicitation whose target is not one of our
// addresses. Anything we can't confidently classify is passed through.
func (e *hostFilterEndpoint) dropInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) bool {
	switch protocol {
	case header.ARPProtocolNumber:
		b, ok := pkt.Data().PullUp(header.ARPSize)
		if !ok {
			return false
		}
		arp := header.ARP(b)
		if arp.Op() != header.ARPRequest {
			// Only requests are filtered; replies must reach the stack
			// so we learn the guests' link addresses.
			return false
		}
		return !e.local.has(tcpip.AddrFrom4Slice(arp.ProtocolAddressTarget()))

	case header.IPv6ProtocolNumber:
		target, ok := neighborSolicitTarget(pkt)
		if !ok {
			return false
		}
		return !e.local.has(target)
	}
	return false
}

// neighborSolicitTarget returns the solicited target address if pkt is an IPv6
// Neighbor Solicitation carried directly over ICMPv6 (no extension headers),
// which is how NS is sent in practice.
func neighborSolicitTarget(pkt *stack.PacketBuffer) (tcpip.Address, bool) {
	b, ok := pkt.Data().PullUp(header.IPv6MinimumSize + header.ICMPv6NeighborSolicitMinimumSize)
	if !ok {
		return tcpip.Address{}, false
	}
	if header.IPv6(b).NextHeader() != uint8(header.ICMPv6ProtocolNumber) {
		return tcpip.Address{}, false
	}
	icmp := header.ICMPv6(b[header.IPv6MinimumSize:])
	if icmp.Type() != header.ICMPv6NeighborSolicit {
		return tcpip.Address{}, false
	}
	return header.NDPNeighborSolicit(icmp.MessageBody()).TargetAddress(), true
}
