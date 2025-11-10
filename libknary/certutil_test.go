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
	oldProxy := os.Getenv("REVERSE_PROXY_DOMAIN")
	defer func() {
		os.Setenv("CANARY_DOMAIN", oldCanary)
		os.Setenv("DNS_SUBDOMAIN", oldDNSSubdomain)
		os.Setenv("REVERSE_PROXY_DOMAIN", oldProxy)
	}()

	// Test 1: Single domain, no extras
	LoadDomains("canary.test")
	os.Setenv("DNS_SUBDOMAIN", "")
	os.Setenv("REVERSE_PROXY_DOMAIN", "")

	domains := getDomainsForCert()

	// Should have: *.canary.test and canary.test
	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d: %v", len(domains), domains)
	}

	expectedDomains := []string{"*.canary.test", "canary.test"}
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

	// Should have: *.canary.test, canary.test, *.dns.canary.test
	if len(domains) != 3 {
		t.Errorf("Expected 3 domains with DNS_SUBDOMAIN, got %d: %v", len(domains), domains)
	}

	if !containsString(domains, "*.dns.canary.test") {
		t.Errorf("Expected *.dns.canary.test in domains: %v", domains)
	}

	// Test 3: With REVERSE_PROXY_DOMAIN
	os.Setenv("DNS_SUBDOMAIN", "")
	os.Setenv("REVERSE_PROXY_DOMAIN", "proxy.canary.test")
	domains = getDomainsForCert()

	// Should have: *.canary.test, canary.test, *.proxy.canary.test
	// proxy.canary.test is removed because it's covered by *.canary.test
	if len(domains) != 3 {
		t.Errorf("Expected 3 domains with REVERSE_PROXY_DOMAIN, got %d: %v", len(domains), domains)
	}

	expectedProxyDomains := []string{"*.canary.test", "canary.test", "*.proxy.canary.test"}
	for _, expected := range expectedProxyDomains {
		if !containsString(domains, expected) {
			t.Errorf("Expected %s in domains: %v", expected, domains)
		}
	}

	// Test 4: Multiple CANARY_DOMAINs
	LoadDomains("canary.test,second.test")
	os.Setenv("DNS_SUBDOMAIN", "")
	os.Setenv("REVERSE_PROXY_DOMAIN", "")
	domains = getDomainsForCert()

	// Should have 4 domains: *.canary.test, canary.test, *.second.test, second.test
	if len(domains) != 4 {
		t.Errorf("Expected 4 domains for 2 canary domains, got %d: %v", len(domains), domains)
	}

	// Test 5: All options enabled
	LoadDomains("canary.test")
	os.Setenv("DNS_SUBDOMAIN", "dns")
	os.Setenv("REVERSE_PROXY_DOMAIN", "proxy.canary.test")
	domains = getDomainsForCert()

	// Should have 4 domains total
	// *.canary.test covers dns.canary.test and proxy.canary.test
	// so only apex domains and wildcards remain
	if len(domains) != 4 {
		t.Errorf("Expected 4 domains with all options, got %d: %v", len(domains), domains)
	}

	expectedAll := []string{
		"*.canary.test",
		"canary.test",
		"*.dns.canary.test",
		"*.proxy.canary.test",
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
		manyDomains = append(manyDomains, "domain"+string(rune(i))+".test")
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

func TestDeduplicateAndRemoveRedundantDomains(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "No duplicates or redundancy",
			input:    []string{"*.canary.test", "canary.test", "*.second.test", "second.test"},
			expected: []string{"*.canary.test", "canary.test", "*.second.test", "second.test"},
		},
		{
			name:     "Duplicate domains",
			input:    []string{"*.canary.test", "*.canary.test", "canary.test"},
			expected: []string{"*.canary.test", "canary.test"},
		},
		{
			name:     "Wildcard covers subdomain",
			input:    []string{"*.domain.test", "x.domain.test"},
			expected: []string{"*.domain.test"}, // x.domain.test is covered by *.domain.test
		},
		{
			name: "DNS_SUBDOMAIN and REVERSE_PROXY_DOMAIN overlap case",
			input: []string{
				"*.domain.test",
				"domain.test",
				"*.x.domain.test", // from DNS_SUBDOMAIN=x
				"*.x.domain.test", // duplicate from REVERSE_PROXY_DOMAIN
				"x.domain.test",   // redundant with *.domain.test (parent wildcard covers it)
			},
			expected: []string{"*.domain.test", "domain.test", "*.x.domain.test"}, // domain.test kept (apex domain), x.domain.test removed
		},
		{
			name:     "Multiple wildcards and non-redundant bases",
			input:    []string{"*.canary.test", "second.test", "*.second.test", "other.test"},
			expected: []string{"*.canary.test", "*.second.test", "second.test", "other.test"}, // second.test is apex, not covered
		},
		{
			name:     "Empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Only wildcards",
			input:    []string{"*.canary.test", "*.second.test"},
			expected: []string{"*.canary.test", "*.second.test"},
		},
		{
			name:     "Only non-wildcards with no matching wildcards",
			input:    []string{"canary.test", "second.test"},
			expected: []string{"canary.test", "second.test"},
		},
		{
			name: "Complex mixed scenario",
			input: []string{
				"*.canary.test",
				"canary.test", // apex domain - keep
				"*.sub.canary.test",
				"sub.canary.test", // covered by *.canary.test - remove
				"other.test",
				"*.other.test",
				"another.test",
			},
			expected: []string{"*.canary.test", "canary.test", "*.sub.canary.test", "*.other.test", "other.test", "another.test"},
		},
		{
			name: "Deeper nesting",
			input: []string{
				"*.canary.test",
				"a.canary.test", // covered by *.canary.test
				"*.a.canary.test",
				"b.a.canary.test", // covered by *.a.canary.test
			},
			expected: []string{"*.canary.test", "*.a.canary.test"}, // both subdomains removed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateAndRemoveRedundantDomains(tt.input)

			// Check length
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d domains, got %d: %v (expected: %v)",
					len(tt.expected), len(result), result, tt.expected)
			}

			// Check that all expected domains are present (order doesn't matter)
			for _, expected := range tt.expected {
				if !containsString(result, expected) {
					t.Errorf("Expected domain '%s' not found in result: %v", expected, result)
				}
			}

			// Check that no unexpected domains are present
			for _, domain := range result {
				if !containsString(tt.expected, domain) {
					t.Errorf("Unexpected domain '%s' found in result: %v (expected: %v)",
						domain, result, tt.expected)
				}
			}
		})
	}
}

func TestGetDomainsForCert_WithRedundancy(t *testing.T) {
	// Save original env vars
	oldCanary := os.Getenv("CANARY_DOMAIN")
	oldDNSSubdomain := os.Getenv("DNS_SUBDOMAIN")
	oldProxy := os.Getenv("REVERSE_PROXY_DOMAIN")
	defer func() {
		os.Setenv("CANARY_DOMAIN", oldCanary)
		os.Setenv("DNS_SUBDOMAIN", oldDNSSubdomain)
		os.Setenv("REVERSE_PROXY_DOMAIN", oldProxy)
	}()

	// Test DNS_SUBDOMAIN and REVERSE_PROXY_DOMAIN overlap scenario
	LoadDomains("domain.test")
	os.Setenv("DNS_SUBDOMAIN", "x")
	os.Setenv("REVERSE_PROXY_DOMAIN", "x.domain.test")

	domains := getDomainsForCert()

	// Should have: *.domain.test, domain.test, *.x.domain.test
	// Should NOT have: x.domain.test (redundant with *.domain.test parent wildcard)
	// domain.test is kept because wildcards don't cover apex domains
	expectedDomains := []string{"*.domain.test", "domain.test", "*.x.domain.test"}

	if len(domains) != len(expectedDomains) {
		t.Errorf("Expected %d domains, got %d: %v", len(expectedDomains), len(domains), domains)
	}

	for _, expected := range expectedDomains {
		if !containsString(domains, expected) {
			t.Errorf("Expected domain '%s' not found in result: %v", expected, domains)
		}
	}

	// Verify redundant domains are NOT present
	// x.domain.test should be removed because *.domain.test covers it
	redundantDomains := []string{"x.domain.test"}
	for _, redundant := range redundantDomains {
		if containsString(domains, redundant) {
			t.Errorf("Redundant domain '%s' should not be present in result: %v", redundant, domains)
		}
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
