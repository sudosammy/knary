package libknary

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const (
	VERSION       = "3.3.0"
	GITHUB        = "https://github.com/sudosammy/knary"
	GITHUBVERSION = "https://raw.githubusercontent.com/sudosammy/knary/master/VERSION"
)

func generateTLSConfig(eTime int) *tls.Config {
	//code taken and modified from here: https://golang.org/src/crypto/tls/generate_cert.go
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	xcrt := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "127.0.0.1",
			Organization: []string{"gokusec"},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"127.0.0.1", "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, eTime),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	crtBytes, e := x509.CreateCertificate(rand.Reader, &xcrt, &xcrt, priv.Public(), priv)
	if e != nil {
		panic(e)
	}

	crt := tls.Certificate{
		Certificate: [][]byte{crtBytes},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{crt},
	}
}

func NewLocalHTTPSTestServer(handler http.Handler, eTime int) *httptest.Server {
	ts := httptest.NewUnstartedServer(handler)
	//get the tls config generated from the function
	config := generateTLSConfig(eTime)
	ts.TLS = config
	ts.StartTLS()
	return ts
}

func TestCheckUpdate(t *testing.T) {
	val, err := CheckUpdate(VERSION, GITHUBVERSION, GITHUB)
	if val == false && err != nil {
		t.Errorf("Cannot check for updates %s", err.Error())
	}
}

func TestLoadBlackList(t *testing.T) {
	createFile()
	f := openFile()

	//case 1 when env variable is not even set
	val, err := LoadBlacklist()
	if val == true && err == nil {
		t.Errorf("Expected to error out since DENYLIST_FILE env variable not set")
	}

	//second case env variable set but file not there
	os.Setenv("DENYLIST_FILE", "somerandomshit.txt")
	val, err = LoadBlacklist()

	if val == true && err == nil {
		t.Errorf("Expected a file error as filename is not present")
	}

	//third case, everything in place including env var and blacklist filename
	os.Setenv("DENYLIST_FILE", "blacklist_test.txt")
	val, err = LoadBlacklist()

	if val == false {
		t.Errorf("Expected file to load without any errors, BUT got: %s", err)
	}

	f.Close()
	deleteFile()
}

func TestStringContains(t *testing.T) {
	string1 := "gokuKaioKen"
	string2 := "goku"

	string3 := "Naruto"
	string4 := "zzz"

	if val := stringContains(string1, string2); val != true {
		//cant think of another meaningful error message, its just broken!
		t.Errorf("String contains is broken")
	}

	if val := stringContains(string3, string4); val == true {
		t.Errorf("String contains is broken")
	}
}

// simply clear the contents of a particular file
// in this case blacklist_test.txt
func clearFileContent(file string) {
	testFile, err := os.OpenFile(file, os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}

	defer testFile.Close()
	testFile.Truncate(0)
	testFile.Seek(0, 0)
}

// write some specific data to some specific file !
func writeDataToFile(data string, f *os.File) {
	entry := []byte(data)
	_, err := f.Write(entry)
	if err != nil {
		panic(err)
	}
}

func createFile() {
	f, err := os.Create("blacklist_test.txt")
	if err != nil {
		panic(err)
	}
	f.Close()
}

func openFile() *os.File {
	f, err := os.OpenFile("blacklist_test.txt", os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	return f
}

func deleteFile() {
	err := os.Remove("blacklist_test.txt")
	if err != nil {
		panic(err)
	}
}

func TestInBlacklist(t *testing.T) {
	os.Setenv("DENYLIST_FILE", "blacklist_test.txt")
	createFile()
	f := openFile()
	LoadBlacklist()
	dom := "mycanary.com"
	//first test is for empty blacklist file
	val := inBlacklist()

	if val == true {
		t.Errorf("Expected false since file is empty, Got true(there is a match)")
	}

	//second test is for an actual entry
	writeDataToFile("mycanary.com", f)
	LoadBlacklist()
	val = inBlacklist(dom)

	if val == false {
		t.Errorf("Expected true since entry is in blacklist but got false")
	}

	//test case for no match
	dom = "google.com"
	clearFileContent("blacklist_test.txt")
	writeDataToFile("mycanary.com", f)
	LoadBlacklist()
	val = inBlacklist(dom)

	if val == true {
		t.Errorf("Expected false since there is no match but got true")
	}

	// last test case to check if it matches x.mycanary.com when blacklist only says mycanary.com

	dom = "dns.mycanary.com"
	val = inBlacklist(dom)

	if val == true {
		t.Errorf("Expected false since it shouldnt match dns.mycanary.com when blacklist says mycanary.com")
	}

	f.Close()
	deleteFile()
}

func TestLoadDomains(t *testing.T) {
	// Test LoadDomains function
	oldDomains := os.Getenv("CANARY_DOMAIN")
	defer os.Setenv("CANARY_DOMAIN", oldDomains)

	// Test with single domain
	err := LoadDomains("example.com")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	domains := GetDomains()
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Errorf("Expected [example.com], got %v", domains)
	}

	// Test with multiple domains
	err = LoadDomains("example.com,test.com,demo.org")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	domains = GetDomains()
	expected := []string{"example.com", "test.com", "demo.org"}
	if len(domains) != 3 {
		t.Errorf("Expected 3 domains, got %d", len(domains))
	}

	for i, expected := range expected {
		if domains[i] != expected {
			t.Errorf("Expected %s at index %d, got %s", expected, i, domains[i])
		}
	}
}

func TestGetFirstDomain(t *testing.T) {
	err := LoadDomains("first.com,second.com,third.com")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	first := GetFirstDomain()
	if first != "first.com" {
		t.Errorf("Expected first.com, got %s", first)
	}
}

func TestReturnSuffix(t *testing.T) {
	err := LoadDomains("example.com,test.org")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test matching domain
	match, suffix := returnSuffix("Host: subdomain.example.com")
	if !match {
		t.Errorf("Expected match for subdomain.example.com")
	}
	if suffix != "example.com" {
		t.Errorf("Expected suffix example.com, got %s", suffix)
	}

	// Test non-matching domain
	match, suffix = returnSuffix("Host: other.domain.net")
	if match {
		t.Errorf("Expected no match for other.domain.net")
	}

	// Test exact match
	match, suffix = returnSuffix("Host: test.org")
	if !match {
		t.Errorf("Expected match for exact domain test.org")
	}
	if suffix != "test.org" {
		t.Errorf("Expected suffix test.org, got %s", suffix)
	}
}

func TestIsRoot(t *testing.T) {
	err := LoadDomains("example.com")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test root domain
	isRootResult, err := isRoot("example.com.")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !isRootResult {
		t.Errorf("Expected true for root domain example.com.")
	}

	// Test subdomain
	isRootResult, err = isRoot("sub.example.com.")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if isRootResult {
		t.Errorf("Expected false for subdomain sub.example.com.")
	}

	// Test non-matching domain
	isRootResult, err = isRoot("other.com.")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if isRootResult {
		t.Errorf("Expected false for non-matching domain other.com.")
	}
}

func TestIsIPv4(t *testing.T) {
	// Test valid IPv4 addresses
	validIPv4 := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"127.0.0.1",
	}

	for _, ip := range validIPv4 {
		if !IsIPv4(ip) {
			t.Errorf("Expected %s to be valid IPv4", ip)
		}
	}

	// Test invalid IPv4 addresses
	invalidIPv4 := []string{
		"2001:db8::1",
		"not.an.ip",
		"256.256.256.256",
		"192.168.1",
		"",
	}

	for _, ip := range invalidIPv4 {
		if IsIPv4(ip) {
			t.Errorf("Expected %s to be invalid IPv4", ip)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	// Test valid IPv6 addresses
	validIPv6 := []string{
		"2001:db8::1",
		"::1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"2001:db8:85a3::8a2e:370:7334",
		"::ffff:192.0.2.1",
	}

	for _, ip := range validIPv6 {
		if !IsIPv6(ip) {
			t.Errorf("Expected %s to be valid IPv6", ip)
		}
	}

	// Test invalid IPv6 addresses
	invalidIPv6 := []string{
		"192.168.1.1",
		"not.an.ip",
		"gggg::1",
		"2001:db8::1::2",
		"",
	}

	for _, ip := range invalidIPv6 {
		if IsIPv6(ip) {
			t.Errorf("Expected %s to be invalid IPv6", ip)
		}
	}
}

func TestSplitPort(t *testing.T) {
	// Test IPv4 with port
	host, port := splitPort("192.168.1.1:8080")
	if host != "192.168.1.1" {
		t.Errorf("Expected host 192.168.1.1, got %s", host)
	}
	if port != 8080 {
		t.Errorf("Expected port 8080, got %d", port)
	}

	// Test IPv4 without port (returns port 0)
	host, port = splitPort("192.168.1.1")
	if host != "192.168.1.1" {
		t.Errorf("Expected host 192.168.1.1, got %s", host)
	}
	if port != 0 {
		t.Errorf("Expected port 0 for IP without port, got %d", port)
	}

	// Test IPv6 with port
	host, port = splitPort("[2001:db8::1]:8080")
	if host != "2001:db8::1" {
		t.Errorf("Expected host 2001:db8::1, got %s", host)
	}
	if port != 8080 {
		t.Errorf("Expected port 8080, got %d", port)
	}

	// Test IPv6 without port (returns port 0)
	host, port = splitPort("2001:db8::1")
	if host != "2001:db8::1" {
		t.Errorf("Expected host 2001:db8::1, got %s", host)
	}
	if port != 0 {
		t.Errorf("Expected port 0 for IPv6 without port, got %d", port)
	}

	// Test hostname with port (splitPort only works with IP addresses, not hostnames)
	host, port = splitPort("example.com:9000")
	if host != "" {
		t.Errorf("Expected empty host for hostname (not IP), got %s", host)
	}
	if port != 0 {
		t.Errorf("Expected port 0 for hostname (not IP), got %d", port)
	}

	// Test invalid input
	host, port = splitPort("invalid")
	if host != "" {
		t.Errorf("Expected empty host for invalid input, got %s", host)
	}
	if port != 0 {
		t.Errorf("Expected port 0 for invalid input, got %d", port)
	}
}

func TestFileExists(t *testing.T) {
	// Create a temporary file
	createFile()
	defer deleteFile()

	// Test existing file
	if !fileExists("blacklist_test.txt") {
		t.Errorf("Expected blacklist_test.txt to exist")
	}

	// Test non-existing file
	if fileExists("nonexistent_file.txt") {
		t.Errorf("Expected nonexistent_file.txt to not exist")
	}
}

func TestLoadAllowlist(t *testing.T) {
	// Test when ALLOWLIST_FILE is not set (function expects error)
	oldAllowlist := os.Getenv("ALLOWLIST_FILE")
	defer os.Setenv("ALLOWLIST_FILE", oldAllowlist)

	os.Setenv("ALLOWLIST_FILE", "")
	result, err := LoadAllowlist()

	if result {
		t.Errorf("Expected false when ALLOWLIST_FILE not set, got %v", result)
	}
	if err == nil {
		t.Errorf("Expected error when ALLOWLIST_FILE not set, got nil")
	}

	// Test with non-existent file
	os.Setenv("ALLOWLIST_FILE", "nonexistent_allowlist.txt")
	result, err = LoadAllowlist()

	if result {
		t.Errorf("Expected false for non-existent file, got %v", result)
	}
	if err == nil {
		t.Errorf("Expected error for non-existent file, got nil")
	}

	// Test with valid allowlist file
	allowlistFile := "allowlist_test.txt"
	f, err := os.Create(allowlistFile)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(allowlistFile)
	defer f.Close()

	// Write test data
	f.WriteString("example.com\n192.168.1.1\ntest-user-agent\n")
	f.Close()

	os.Setenv("ALLOWLIST_FILE", allowlistFile)
	result, err = LoadAllowlist()

	if !result {
		t.Errorf("Expected true when loading valid allowlist file, got %v", result)
	}
	if err != nil {
		t.Errorf("Expected no error when loading valid allowlist file, got %v", err)
	}
}

func TestInAllowlist(t *testing.T) {
	// Test with empty allowlist (should return true - allow everything)
	oldAllowlist := os.Getenv("ALLOWLIST_FILE")
	defer os.Setenv("ALLOWLIST_FILE", oldAllowlist)

	os.Setenv("ALLOWLIST_FILE", "")
	LoadAllowlist()

	result := inAllowlist("user-agent", "example.com", "192.168.1.1", "")
	if !result {
		t.Errorf("Expected true for empty allowlist (allow all), got false")
	}

	// Test with populated allowlist
	allowlistFile := "allowlist_test.txt"
	f, err := os.Create(allowlistFile)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(allowlistFile)

	f.WriteString("example.com\n192.168.1.1\ntest-user-agent\n")
	f.Close()

	os.Setenv("ALLOWLIST_FILE", allowlistFile)
	LoadAllowlist()

	// Test domain match
	result = inAllowlist("", "example.com", "", "")
	if !result {
		t.Errorf("Expected true for domain in allowlist")
	}

	// Test IP match
	result = inAllowlist("", "", "192.168.1.1", "")
	if !result {
		t.Errorf("Expected true for IP in allowlist")
	}

	// Test user-agent match
	result = inAllowlist("test-user-agent", "", "", "")
	if !result {
		t.Errorf("Expected true for user-agent in allowlist")
	}

	// Test no match
	result = inAllowlist("other-agent", "other.com", "10.0.0.1", "")
	if result {
		t.Errorf("Expected false for items not in allowlist")
	}
}
