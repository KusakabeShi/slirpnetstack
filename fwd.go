package main

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Listener interface {
	Close() error
	Addr() net.Addr
}

func LocalForwardTCP(state *State, s *stack.Stack, rf FwdAddr, doneChannel <-chan bool) (Listener, error) {
	tmpBind := &net.TCPAddr{
		IP:   net.IP(rf.bind.Addr),
		Port: int(rf.bind.Port),
	}

	host := &net.TCPAddr{
		IP:   net.IP(rf.host.Addr),
		Port: int(rf.host.Port),
	}

	srv, err := net.ListenTCP(rf.network, tmpBind)
	if err != nil {
		return nil, err
	}

	go func() error {
		for {
			nRemote, err := srv.Accept()
			if err != nil {
				// Not sure when Accept() can error,
				// nor what the correct resolution
				// is. Most likely socket is closed.
				return err
			}
			remote := &KaTCPConn{nRemote.(*net.TCPConn)}

			go func() {
				LocalForward(state, s, remote, host, nil, rf.proxyProtocol)
			}()
		}
	}()

	return srv, nil
}

type UDPListner struct {
	*net.UDPConn
}

func (u *UDPListner) Addr() net.Addr {
	return u.UDPConn.LocalAddr()
}

func LocalForwardUDP(state *State, s *stack.Stack, rf FwdAddr, doneChannel <-chan bool) (Listener, error) {
	tmpBind := &net.UDPAddr{
		IP:   net.IP(rf.bind.Addr),
		Port: int(rf.bind.Port),
	}

	host := &net.UDPAddr{
		IP:   net.IP(rf.host.Addr),
		Port: int(rf.host.Port),
	}

	srv, err := net.ListenUDP(rf.network, tmpBind)
	if err != nil {
		return nil, err
	}

	SetReuseaddr(srv)

	laddr := srv.LocalAddr().(*net.UDPAddr)

	go func() error {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := srv.ReadFrom(buf)
			if err != nil {
				return err
			}
			raddr := addr.(*net.UDPAddr)

			// Warning, this is racy, what if two packets are in the queue?
			remote, err := MagicDialUDP(laddr, raddr)
			if err != nil {
				// This actually can totally happen in
				// the said race. Just drop the packet then.
				continue
			}

			if rf.kaEnable && rf.kaInterval == 0 {
				remote.closeOnWrite = true
			}

			go func() {
				LocalForward(state, s, remote, host, buf[:n], rf.proxyProtocol)
			}()
		}
	}()
	return &UDPListner{srv}, nil
}

func LocalForward(state *State, s *stack.Stack, host KaConn, gaddr net.Addr, buf []byte, proxyProtocol bool) {
	var (
		err          error
		raddr        = host.RemoteAddr()
		ppSrc, ppDst net.Addr
		sppHeader    []byte
	)
	if proxyProtocol && buf == nil {
		buf = make([]byte, 4096)
		n, err := host.Read(buf)
		if err != nil {
			goto pperror
		}
		buf = buf[:n]
	}

	if proxyProtocol {
		var (
			n int
		)
		if gaddr.Network() == "tcp" {
			n, ppSrc, ppDst, err = DecodePP(buf)
			buf = buf[n:]
		} else {
			n, ppSrc, ppDst, err = DecodeSPP(buf)
			sppHeader = make([]byte, n)
			copy(sppHeader, buf[:n])
			buf = buf[n:]
		}
		if err != nil {
			goto pperror
		}
	}

	{
		var (
			srcIP    net.Addr
			ppPrefix = ""
		)
		if proxyProtocol == false {
			// When doing local forward, if the source IP of host
			// connection had routable IP (unlike
			// 127.0.0.1)... well... spoof it! The client might find it
			// useful who launched the connection in the first place.
			if IPNetContains(state.RoutingDeny, netAddrIP(raddr)) == false {
				srcIP = raddr
			}
		} else {
			ppPrefix = "PP "
			if IPNetContains(state.RoutingDeny, netAddrIP(ppSrc)) == false {
				srcIP = ppSrc
			} else {
				// If the source IP as reported by PP
				// is not routable, still forward
				// connection. Just don't use/leak the
				// original IP.
			}
		}
		if srcIP != nil {
			// It's very nice the proxy-protocol (or just
			// client) gave us client port number, but we
			// don't want it. Spoofing the same port
			// number on our side is not safe, useless,
			// confusing and very bug prone.
			srcIP = netAddrSetPort(srcIP, 0)
		}

		if netAddrPort(gaddr) == 0 {
			// If the guest has dport equal to zero, fill
			// it up somehow. First guess - use dport of
			// host connection.
			hostPort := netAddrPort(host.LocalAddr())

			// Alternatively if we got dport from PP, use that
			if ppDst != nil {
				hostPort = netAddrPort(ppDst)
			}

			gaddr = netAddrSetPort(gaddr, hostPort)
		}

		if logConnections {
			fmt.Printf("[+] %s://%s/%s/%s local-fwd %sconn\n",
				gaddr.Network(),
				raddr,
				host.LocalAddr(),
				gaddr.String(),
				ppPrefix)
		}

		guest, err := GonetDial(s, srcIP, gaddr)

		var pe ProxyError
		if err != nil {
			SetResetOnClose(host)
			host.Close()
			pe.RemoteRead = fmt.Errorf("%s", err)
			pe.First = 2
		} else {
			guest.Write(buf)
			pe = connSplice(host, guest, sppHeader)
		}
		if logConnections {
			fmt.Printf("[-] %s://%s/%s/%s (guest-src:%s) local-fwd %sdone: %s\n",
				gaddr.Network(),
				raddr,
				host.LocalAddr(),
				gaddr.String(),
				guest.LocalAddr(),
				ppPrefix,
				pe)
		}
	}
	return
pperror:
	if logConnections {
		fmt.Printf("[!] %s://%s/%s/%s local-fwd PP error: %s\n",
			gaddr.Network(),
			raddr,
			host.LocalAddr(),
			gaddr.String(),
			err)
	}
	host.Close()
	return
}
