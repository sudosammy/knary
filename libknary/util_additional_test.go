package libknary

import (
	"os"
	"testing"
)

func TestSignLark(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		timestamp int64
		wantErr   bool
	}{
		{
			name:      "valid signature",
			secret:    "test-secret-key",
			timestamp: 1609459200, // 2021-01-01 00:00:00 UTC
			wantErr:   false,
		},
		{
			name:      "empty secret",
			secret:    "",
			timestamp: 1609459200,
			wantErr:   false, // Function doesn't return error for empty secret
		},
		{
			name:      "zero timestamp",
			secret:    "test-secret",
			timestamp: 0,
			wantErr:   false,
		},
		{
			name:      "negative timestamp",
			secret:    "test-secret",
			timestamp: -1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := SignLark(tt.secret, tt.timestamp)

			if (err != nil) != tt.wantErr {
				t.Errorf("SignLark() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				// Signature should be a base64-encoded string
				if signature == "" {
					t.Errorf("SignLark() returned empty signature")
				}

				// Same inputs should produce same signature
				signature2, err2 := SignLark(tt.secret, tt.timestamp)
				if err2 != nil {
					t.Errorf("Second SignLark() call failed: %v", err2)
				}
				if signature != signature2 {
					t.Errorf("SignLark() not deterministic: %s != %s", signature, signature2)
				}
			}
		})
	}
}

func TestIsDeprecated(t *testing.T) {
	// Save old env and setup test
	oldSlack := os.Getenv("SLACK_WEBHOOK")
	testServer := "http://localhost:9999" // Use a localhost address that won't be reachable
	os.Setenv("SLACK_WEBHOOK", testServer)
	defer os.Setenv("SLACK_WEBHOOK", oldSlack)

	// Test that IsDeprecated doesn't panic
	// It logs and sends a message, but we can't easily test that without mocking
	IsDeprecated("OLD_VAR", "NEW_VAR", "4.0.0")

	// If we get here without panic, test passes
	// The function logs and sends a webhook, but we're just ensuring it doesn't crash
}

func TestIsIP_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "localhost",
			input:    "localhost",
			expected: false,
		},
		{
			name:     "IPv4 with leading zeros",
			input:    "192.168.001.001",
			expected: false, // Go's net.ParseIP actually rejects this
		},
		{
			name:     "IPv4 with extra digits",
			input:    "999.999.999.999",
			expected: false,
		},
		{
			name:     "IPv6 abbreviated",
			input:    "::1",
			expected: true,
		},
		{
			name:     "IPv6 full",
			input:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: true,
		},
		{
			name:     "IPv4-mapped IPv6",
			input:    "::ffff:192.0.2.1",
			expected: true,
		},
		{
			name:     "malformed IP",
			input:    "192.168.1",
			expected: false,
		},
		{
			name:     "IP with port",
			input:    "192.168.1.1:8080",
			expected: false, // IsIP doesn't handle ports
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIP(tt.input)
			if result != tt.expected {
				t.Errorf("IsIP(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStringContains_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		haystack string
		needle   string
		expected bool
	}{
		{
			name:     "exact match",
			haystack: "example",
			needle:   "example",
			expected: true,
		},
		{
			name:     "case insensitive match",
			haystack: "Example.Com",
			needle:   "example.com",
			expected: true,
		},
		{
			name:     "substring match",
			haystack: "this is an example",
			needle:   "EXAMPLE",
			expected: true,
		},
		{
			name:     "no match",
			haystack: "example",
			needle:   "test",
			expected: false,
		},
		{
			name:     "empty needle",
			haystack: "example",
			needle:   "",
			expected: true, // Empty string is contained in everything
		},
		{
			name:     "empty haystack",
			haystack: "",
			needle:   "test",
			expected: false,
		},
		{
			name:     "both empty",
			haystack: "",
			needle:   "",
			expected: true,
		},
		{
			name:     "unicode characters",
			haystack: "Tëst Ëxamplë",
			needle:   "ëxamplë",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringContains(tt.haystack, tt.needle)
			if result != tt.expected {
				t.Errorf("stringContains(%q, %q) = %v, want %v", tt.haystack, tt.needle, result, tt.expected)
			}
		})
	}
}

func TestLoadDomains_WithSpaces(t *testing.T) {
	// Test that LoadDomains handles spaces correctly
	tests := []struct {
		name          string
		input         string
		expectedCount int
		expectedFirst string
	}{
		{
			name:          "domains with spaces",
			input:         "example.com, test.com, demo.org",
			expectedCount: 3,
			expectedFirst: "example.com",
		},
		{
			name:          "domains without spaces",
			input:         "example.com,test.com,demo.org",
			expectedCount: 3,
			expectedFirst: "example.com",
		},
		{
			name:          "single domain",
			input:         "example.com",
			expectedCount: 1,
			expectedFirst: "example.com",
		},
		{
			name:          "domains with extra spaces",
			input:         "  example.com  ,  test.com  ",
			expectedCount: 2,
			expectedFirst: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := LoadDomains(tt.input)
			if err != nil {
				t.Errorf("LoadDomains() error = %v", err)
				return
			}

			domains := GetDomains()
			if len(domains) != tt.expectedCount {
				t.Errorf("Expected %d domains, got %d: %v", tt.expectedCount, len(domains), domains)
			}

			if len(domains) > 0 && domains[0] != tt.expectedFirst {
				t.Errorf("Expected first domain %q, got %q", tt.expectedFirst, domains[0])
			}
		})
	}
}

func TestReturnSuffix_WithPort(t *testing.T) {
	// Setup test domains
	LoadDomains("example.com")

	tests := []struct {
		name         string
		input        string
		expectMatch  bool
		expectSuffix string
	}{
		{
			name:         "domain with port",
			input:        "Host: test.example.com:8080",
			expectMatch:  true,
			expectSuffix: "example.com",
		},
		{
			name:         "domain with standard port",
			input:        "Host: test.example.com:80",
			expectMatch:  true,
			expectSuffix: "example.com",
		},
		{
			name:         "domain without port",
			input:        "Host: test.example.com",
			expectMatch:  true,
			expectSuffix: "example.com",
		},
		{
			name:         "no match with port",
			input:        "Host: test.other.com:8080",
			expectMatch:  false,
			expectSuffix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, suffix := returnSuffix(tt.input)
			if match != tt.expectMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectMatch, match)
			}
			if suffix != tt.expectSuffix {
				t.Errorf("Expected suffix=%q, got %q", tt.expectSuffix, suffix)
			}
		})
	}
}
