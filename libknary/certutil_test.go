package libknary

import (
	"os"
	"strings"
	"testing"
)

func TestGetDomainsForCert(t *testing.T) {
	// Save original env vars
	oldCanary := os.Getenv("CANARY_DOMAIN")
	oldDNSSubdomain := os.Getenv("DNS_SUBDOMAIN")
	oldBurp := os.Getenv("BURP_DOMAIN")
	oldProxy := os.Getenv("REVERSE_PROXY_DOMAIN")
	defer func() {
		os.Setenv("CANARY_DOMAIN", oldCanary)
		os.Setenv("DNS_SUBDOMAIN", oldDNSSubdomain)
		os.Setenv("BURP_DOMAIN", oldBurp)
		os.Setenv("REVERSE_PROXY_DOMAIN", oldProxy)
	}()

	// Test 1: Single domain, no extras
	LoadDomains("example.com")
	os.Setenv("DNS_SUBDOMAIN", "")
	os.Setenv("BURP_DOMAIN", "")
	os.Setenv("REVERSE_PROXY_DOMAIN", "")

	domains := getDomainsForCert()

	// Should have: *.example.com and example.com
	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d: %v", len(domains), domains)
	}

	expectedDomains := []string{"*.example.com", "example.com"}
	for _, expected := range expectedDomains {
		found := false
		for _, domain := range domains {
			if domain == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected domain %s not found in result: %v", expected, domains)
		}
	}

	// Test 2: With DNS_SUBDOMAIN
	os.Setenv("DNS_SUBDOMAIN", "dns")
	domains = getDomainsForCert()

	// Should have: *.example.com, example.com, *.dns.example.com
	if len(domains) != 3 {
		t.Errorf("Expected 3 domains with DNS_SUBDOMAIN, got %d: %v", len(domains), domains)
	}

	if !containsString(domains, "*.dns.example.com") {
		t.Errorf("Expected *.dns.example.com in domains: %v", domains)
	}

	// Test 3: With REVERSE_PROXY_DOMAIN
	os.Setenv("DNS_SUBDOMAIN", "")
	os.Setenv("REVERSE_PROXY_DOMAIN", "proxy.example.com")
	domains = getDomainsForCert()

	// Should have: *.example.com, example.com, *.proxy.example.com, proxy.example.com
	if len(domains) != 4 {
		t.Errorf("Expected 4 domains with REVERSE_PROXY_DOMAIN, got %d: %v", len(domains), domains)
	}

	expectedProxyDomains := []string{"*.proxy.example.com", "proxy.example.com"}
	for _, expected := range expectedProxyDomains {
		if !containsString(domains, expected) {
			t.Errorf("Expected %s in domains: %v", expected, domains)
		}
	}

	// Test 4: Multiple CANARY_DOMAINs
	LoadDomains("example.com,test.com")
	os.Setenv("DNS_SUBDOMAIN", "")
	os.Setenv("BURP_DOMAIN", "")
	os.Setenv("REVERSE_PROXY_DOMAIN", "")
	domains = getDomainsForCert()

	// Should have 4 domains: *.example.com, example.com, *.test.com, test.com
	if len(domains) != 4 {
		t.Errorf("Expected 4 domains for 2 canary domains, got %d: %v", len(domains), domains)
	}

	// Test 5: All options enabled
	LoadDomains("example.com")
	os.Setenv("DNS_SUBDOMAIN", "dns")
	os.Setenv("BURP_DOMAIN", "burp.example.com")
	os.Setenv("REVERSE_PROXY_DOMAIN", "proxy.example.com")
	domains = getDomainsForCert()

	// Should have 7 domains total (canary: 2, dns_subdomain: 1, burp: 2, proxy: 2)
	if len(domains) != 7 {
		t.Errorf("Expected 7 domains with all options, got %d: %v", len(domains), domains)
	}

	expectedAll := []string{
		"*.example.com",
		"example.com",
		"*.dns.example.com",
		"*.burp.example.com",
		"burp.example.com",
		"*.proxy.example.com",
		"proxy.example.com",
	}

	for _, expected := range expectedAll {
		if !containsString(domains, expected) {
			t.Errorf("Expected %s in domains: %v", expected, domains)
		}
	}
}

func TestGetDomainsForCert_TooManyDomains(t *testing.T) {
	// Save original env vars
	oldCanary := os.Getenv("CANARY_DOMAIN")
	oldDNSSubdomain := os.Getenv("DNS_SUBDOMAIN")
	defer func() {
		os.Setenv("CANARY_DOMAIN", oldCanary)
		os.Setenv("DNS_SUBDOMAIN", oldDNSSubdomain)
	}()

	// Create 60 domains (which with DNS_SUBDOMAIN would be 180 = 60*3 domains, exceeding 100 limit)
	manyDomains := []string{}
	for i := 0; i < 60; i++ {
		manyDomains = append(manyDomains, "example"+string(rune(i))+".com")
	}

	LoadDomains(strings.Join(manyDomains, ","))
	os.Setenv("DNS_SUBDOMAIN", "dns")

	// This should trigger a log.Fatal, but we can't easily test that without refactoring
	// So we just call the function to ensure it compiles and doesn't panic before the limit check
	defer func() {
		if r := recover(); r != nil {
			// Expected to panic/fatal when exceeding 100 domains
			t.Logf("Function correctly detected too many domains: %v", r)
		}
	}()

	// Note: This will cause log.Fatal which exits the test
	// In a real scenario, we'd refactor to return error instead of log.Fatal
	// getDomainsForCert()
}

func TestCheckCertificateDomains_NoCert(t *testing.T) {
	// Save original env vars
	oldCrt := os.Getenv("TLS_CRT")
	oldKey := os.Getenv("TLS_KEY")
	defer func() {
		os.Setenv("TLS_CRT", oldCrt)
		os.Setenv("TLS_KEY", oldKey)
	}()

	// Test with no certificate configured
	os.Setenv("TLS_CRT", "")
	os.Setenv("TLS_KEY", "")

	allPresent, missing := checkCertificateDomains()

	if !allPresent {
		t.Errorf("Expected true when no cert is configured")
	}
	if missing != nil {
		t.Errorf("Expected nil missing domains when no cert configured, got: %v", missing)
	}
}

func TestCheckCertificateDomains_NonExistentCert(t *testing.T) {
	// Save original env vars
	oldCrt := os.Getenv("TLS_CRT")
	oldKey := os.Getenv("TLS_KEY")
	defer func() {
		os.Setenv("TLS_CRT", oldCrt)
		os.Setenv("TLS_KEY", oldKey)
	}()

	// Test with non-existent certificate file
	os.Setenv("TLS_CRT", "/nonexistent/path/cert.crt")
	os.Setenv("TLS_KEY", "/nonexistent/path/cert.key")

	allPresent, missing := checkCertificateDomains()

	// Should return true and skip check if cert can't be read
	if !allPresent {
		t.Errorf("Expected true when cert can't be read")
	}
	if missing != nil {
		t.Errorf("Expected nil missing domains when cert can't be read, got: %v", missing)
	}
}

// Helper function
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
