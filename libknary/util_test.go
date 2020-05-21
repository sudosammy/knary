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
	"strings"
	"testing"
	"time"
)

const (
	VERSION       = "2.2.4"
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

func TestTLSExpiryCase1(t *testing.T) {
	//first case is when certificate expires in less tha 8 days
	dom := "127.0.0.1"
	ts := NewLocalHTTPSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), 8)
	port := strings.SplitAfter(ts.URL, ":")[2]
	os.Setenv("TLS_PORT", port)
	defer ts.Close()

	// its self signed so need to skip any checks
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	val, err := CheckTLSExpiry(dom, conf)

	if val == false && err != nil {
		t.Errorf(err.Error())
	}

	if val == true {
		t.Errorf("Expected False(certificate expiry < 10 days) But got True(not expiring in < 10 days)")
	}

}

func TestTLSExpiryCase2(t *testing.T) {
	//second case is when certificate is all well and good with expiry > 10 days
	dom := "127.0.0.1"
	ts := NewLocalHTTPSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), 12)
	port := strings.SplitAfter(ts.URL, ":")[2]
	os.Setenv("TLS_PORT", port)
	defer ts.Close()

	// its self signed so need to skip any checks
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	val, err := CheckTLSExpiry(dom, conf)

	if val == false && err != nil {
		t.Errorf(err.Error())
	}

	if val == false && err == nil {
		t.Errorf("Expected True(Certificate expiry > 10 days) But got False(expiring in < 10 days)")
	}
}

func TestTLSExpiryCase3(t *testing.T) {
	//third case when expiry is negative !(jeez come on)
	dom := "127.0.0.1"
	ts := NewLocalHTTPSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), -1)
	port := strings.SplitAfter(ts.URL, ":")[2]
	os.Setenv("TLS_PORT", port)
	defer ts.Close()

	// its self signed so need to skip any checks
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	val, err := CheckTLSExpiry(dom, conf)

	if val == false && err != nil {
		t.Errorf(err.Error())
	}

	if val == true {
		t.Errorf("Expected False(Certificate expiry is negative) But got True(not expiring in > 10 days)")
	}
}

func TestCheckUpdate(t *testing.T) {
	val, err := CheckUpdate(VERSION, GITHUBVERSION, GITHUB)
	if val == false && err != nil {
		t.Errorf("Cannot check for updates %s", err.Error())
	}
}

func TestLoadBlackList(t *testing.T) {
	createFile()
	//case 1 when env variable is not even set
	val, err := LoadBlacklist()
	if val == true && err == nil {
		t.Errorf("Expected to error out since BLACKLIST_FILE env variable not set")
	}

	//second case env variable set but file not there
	os.Setenv("BLACKLIST_FILE", "somerandomshit.txt")
	val, err = LoadBlacklist()

	if val == true && err == nil {
		t.Errorf("Expected a file error as filename is not present")
	}

	//third case, everything in place including env var and blacklist filename
	os.Setenv("BLACKLIST_FILE", "blacklist_test.txt")
	val, err = LoadBlacklist()

	if val == false {
		t.Errorf("Expected file to load without any errors, BUT got: %s", err)
	}
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

//simply clear the contents of a particular file
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

//write some specific data to some specific file !
func writeDataToFile(data string, f *os.File) {
	entry := []byte(data)
	_, err := f.Write(entry)
	if err != nil {
		panic(err)
	}
}

func createFile() *os.File {
	f, err := os.Create("blacklist_test.txt")
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
	os.Setenv("BLACKLIST_FILE", "blacklist_test.txt")
	f := createFile()
	defer f.Close()
	LoadBlacklist()
	dom := "mycanary.com"
	//first test is for empty blacklist file
	val := inBlacklist()

	if val == true {
		t.Errorf("Expected false since file is emtpy, Got true(there is a match)")
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
	deleteFile()

}
