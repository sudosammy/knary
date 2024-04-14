package libknary

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAcceptDNS(t *testing.T) {
	// Set up test environment
	os.Setenv("BIND_ADDR", "127.0.0.1")

	// Skip test if user can't bind to port 53
	server := &dns.Server{Addr: os.Getenv("BIND_ADDR") + ":53", Net: "udp"}
	err := server.ListenAndServe()

	// If err contains "permission denied", skip the test
	if err != nil && strings.Contains(err.Error(), "permission denied") {
		t.Skip("Test requires root privileges")
	}

	// Create a wait group to synchronize goroutines
	var wg sync.WaitGroup
	wg.Add(1)

	// Start the DNS server in a goroutine
	go AcceptDNS(&wg)

	// Wait for the DNS server to start
	time.Sleep(time.Second)

	// Send a DNS query to the server
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	c := new(dns.Client)
	_, _, err = c.Exchange(m, "127.0.0.1")
	if err != nil {
		t.Errorf("Failed to send DNS query: %v", err)
	}

	// Wait for the DNS server to finish
	wg.Wait()
}

func TestInfoLog(t *testing.T) {
	ipaddr := "127.0.0.1"
	reverse := "example.com"
	name := "example"
	infoLog(ipaddr, reverse, name)

	// There are no assertions in this test at the moment
}
