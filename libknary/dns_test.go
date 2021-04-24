package libknary

import (
	"github.com/miekg/dns"
	"net"
	"sync"
	"time"
)

//code for 3 functions below here is taken and modified from
//here: https://github.com/miekg/dns/blob/67373879ce327b5fd112d9301d0a4d62bad6b904/server_test.go
func GokuServer(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	//no idea why m.Extra doesnt work but m.Answer does
	//m.Extra = make([]dns.RR, 1)
	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassANY}, A: net.IPv4(127, 0, 0, 1)}
	w.WriteMsg(m)
}

func RunLocalUDPServer(laddr string) (*dns.Server, string, error) {
	server, l, _, err := RunLocalUDPServerWithFinChan(laddr)

	return server, l, err
}

func RunLocalUDPServerWithFinChan(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	// fin must be buffered so the goroutine below won't block
	// forever if fin is never read from. This always happens
	// in RunLocalUDPServer and can happen in TestShutdownUDP.
	fin := make(chan error, 1)

	for _, opt := range opts {
		opt(server)
	}

	go func() {
		fin <- server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()
	return server, pc.LocalAddr().String(), fin, nil
}
