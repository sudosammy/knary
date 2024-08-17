package libknary

import (
	"os"
	"testing"

	"github.com/miekg/dns"
)

func TestLoadZone_WhenZoneFileExists_ReturnsTrueAndNoError(t *testing.T) {
	os.Setenv("ZONE_FILE", ".zone_test.txt")
	if err := os.WriteFile(".zone_test.txt", []byte("example.com. IN A 192.0.2.1"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(".zone_test.txt")

	result, err := LoadZone()

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != true {
		t.Error("Expected result to be true")
	}
}

func TestLoadZone_WhenZoneFileInvalid_ReturnsError(t *testing.T) {
	os.Setenv("ZONE_FILE", ".zone_test.txt")
	// No trailing period
	if err := os.WriteFile(".zone_test.txt", []byte("example.com IN A 192.0.2.1"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(".zone_test.txt")

	result, err := LoadZone()

	if err == nil {
		t.Errorf("Expected an error")
	}
	if result == true {
		t.Error("Expected result to be false")
	}
}

func TestLoadZone_WhenZoneFileDoesNotExist_ReturnsFalseAndError(t *testing.T) {
	os.Setenv("ZONE_FILE", "nonexistent.txt")

	result, err := LoadZone()

	if err == nil {
		t.Error("Expected an error")
	}
	if result != false {
		t.Error("Expected result to be false")
	}
}

func TestAddZone_WhenValidInput_ReturnsNoError(t *testing.T) {
	err := addZone("example.com", 3600, "A", "192.0.2.1")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestAddZone_WhenInvalidInput_ReturnsError(t *testing.T) {
	err := addZone("example.com", 3600, "InvalidType", "192.0.2.1")

	if err == nil {
		t.Error("Expected an error")
	}
}

func TestInZone_WhenZoneExists_ReturnsNoError(t *testing.T) {
	fqdn := "example.com"
	addZone(fqdn, 3600, "A", "192.0.2.1")

	rr, foundInZone := inZone(fqdn, dns.TypeA)

	if rr == nil {
		t.Error("Expected RR not found")
	}

	if foundInZone != true {
		t.Error("Expected zone not found")
	}
}

func TestInZone_WhenZoneDoesNotExist_ReturnsNoError(t *testing.T) {
	rr, foundInZone := inZone("not-exists.com", dns.TypeA)

	if rr != nil {
		t.Error("Unexpected RR found")
	}

	if foundInZone != false {
		t.Error("Unexpected zone found")
	}
}

func TestRemZone_WhenZoneExists_DeletesZoneAndReturnsNoError(t *testing.T) {
	fqdn := "another-example.com"
	err := addZone(fqdn, 3600, "A", "192.0.2.1")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	remZone(fqdn)

	// Check if zone is deleted
	_, foundInZone := inZone(fqdn, dns.TypeA)
	if foundInZone == true {
		t.Error("Expected zone not deleted")
	}
}

func TestRemZone_WhenZoneDoesNotExist_DoesNotDeleteZoneAndReturnsNoError(t *testing.T) {
	fqdn := "another-example.com"
	err := addZone(fqdn, 3600, "A", "192.0.2.2")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	remZone("not-exists.com")

	// Check if zone is not deleted
	_, foundInZone := inZone(fqdn, dns.TypeA)
	if foundInZone != true {
		t.Error("Unexpected zone deleted")
	}
}
