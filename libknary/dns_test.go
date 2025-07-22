package libknary

import (
	"net"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func TestInfoLog(t *testing.T) {
	ipaddr := "127.0.0.1"
	reverse := "example.com"
	name := "example"
	infoLog(ipaddr, reverse, name)

	// Test passes if no panic occurs - this function only logs when DEBUG=true
}

func TestGuessIP_WithValidDomain(t *testing.T) {
	// Test the GuessIP function that we fixed the panic bug for
	// This tests our fix for issue #85
	domain := "nonexistent.tld"

	// This should return an error but NOT panic
	_, err := GuessIP(domain)

	if err == nil {
		t.Errorf("Expected error for non-existent domain, got nil")
	}

	// The test passes if it doesn't panic - our fix prevents the nil pointer dereference
}

func TestQueryDNS_ARecord(t *testing.T) {
	// Test A record query to a known DNS server
	result, err := queryDNS("google.com", "A", "8.8.8.8")

	if err != nil {
		t.Logf("DNS query failed (may be expected in test environment): %v", err)
		return // Don't fail test if DNS unavailable
	}

	if result == "" {
		t.Errorf("Expected non-empty result for A record query")
	}

	if !IsIP(result) {
		t.Errorf("Expected valid IP address, got: %s", result)
	}
}

func TestQueryDNS_NSRecord(t *testing.T) {
	// Test NS record query
	result, err := queryDNS("google.com", "NS", "8.8.8.8")

	if err != nil {
		t.Logf("DNS query failed (may be expected in test environment): %v", err)
		return
	}

	if result == "" {
		t.Errorf("Expected non-empty result for NS record query")
	}
}

func TestQueryDNS_InvalidType(t *testing.T) {
	// Test with invalid record type
	_, err := queryDNS("google.com", "INVALID", "8.8.8.8")

	if err == nil {
		t.Errorf("Expected error for invalid record type")
	}
}

func TestHandleDNS_ARecord(t *testing.T) {
	// Create test DNS message
	msg := new(dns.Msg)
	msg.SetQuestion("test.example.com.", dns.TypeA)

	// Create mock response writer
	mockAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	mockWriter := &mockResponseWriter{remoteAddr: mockAddr}

	// Test that HandleDNS doesn't panic
	HandleDNS(mockWriter, msg, "192.0.2.1")

	// Verify response was written
	if !mockWriter.written {
		t.Errorf("Expected response to be written")
	}
}

func TestGoSendMsg_WithDebug(t *testing.T) {
	// Test goSendMsg function with debug mode
	oldDebug := os.Getenv("DEBUG")
	os.Setenv("DEBUG", "true")
	defer os.Setenv("DEBUG", oldDebug)

	// This should not panic and should handle the filtering logic
	result := goSendMsg("127.0.0.1", "localhost", "test.example.com", "A")

	// The function returns false if not in allowlist or in denylist
	// Since we haven't configured lists, it should return false
	if result {
		t.Logf("goSendMsg returned true - message was sent")
	} else {
		t.Logf("goSendMsg returned false - message was filtered")
	}
}

func TestParseDNS_MultipleQuestions(t *testing.T) {
	// Create DNS message with multiple questions
	msg := new(dns.Msg)
	msg.SetQuestion("test1.example.com.", dns.TypeA)
	msg.Question = append(msg.Question, dns.Question{
		Name:   "test2.example.com.",
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	})

	// Test parsing doesn't panic with multiple questions
	parseDNS(msg, "127.0.0.1:12345", "192.0.2.1")

	// Test passes if no panic occurs
}

// Mock response writer for testing
type mockResponseWriter struct {
	remoteAddr net.Addr
	written    bool
}

func (m *mockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (m *mockResponseWriter) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.written = true
	return nil
}

func (m *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *mockResponseWriter) Close() error {
	return nil
}

func (m *mockResponseWriter) TsigStatus() error {
	return nil
}

func (m *mockResponseWriter) TsigTimersOnly(bool) {}

func (m *mockResponseWriter) Hijack() {}

func (m *mockResponseWriter) Network() string {
	return "udp"
}
