package libknary

import (
	"net"
	"sync"
	"testing"
	//"fmt"
	"github.com/miekg/dns"
	"os"
	"time"
)

//func TestAcceptDns(t *testing.T) {
//    var wg sync.WaitGroup
//    wg.Add(1)
//    go AcceptDNS(&wg)
//
//    _, err := net.Listen("udp", ":53")
//    if err == nil {
//        t.Errorf("DNS Server not running")
//    } else {
//        t.Log("Successfully started DNS server on port 53")
//        fmt.Println("DONE")
//    }
//    wg.Wait()

//}

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

func TestPerformALookup(t *testing.T) {
	dns.HandleFunc("goku.lab.sec.", GokuServer)
	defer dns.HandleRemove("goku.lab.sec.")

	s, _, err := RunLocalUDPServer(":53")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("goku.lab.sec.", dns.TypeA)

	os.Setenv("DNS_SERVER", "127.0.0.1")
	lookupString := "goku.lab.sec"
	strng, err := PerformALookup(lookupString)

	if err != nil {
		t.Errorf("Cannot Perform Lookup: %v", err)
	} else if strng == "" && err == nil {
		t.Errorf("Cannot Perform Lookup")
	}

	if strng != "127.0.0.1" && err == nil {
		t.Errorf("Got %s, Expected 127.0.0.1", strng)
	}
}
