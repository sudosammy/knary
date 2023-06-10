package libknary

import (
	"os"
	"testing"
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
