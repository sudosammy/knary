package libknary

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sudosammy/knary/libknary/lego"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/registration"
)

// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt("CERTBOT_TTL", 120),
		PropagationTimeout: env.GetOrDefaultSecond("CERTBOT_PROPAGATION_TIMEOUT", 1*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond("CERTBOT_POLLING_INTERVAL", 2*time.Second),
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
}

func NewDNSProvider() (*DNSProvider, error) {
	config := NewDefaultConfig()
	return NewDNSProviderConfig(config)
}

func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("There was an error getting the configuration for Lets Encrypt")
	}

	return &DNSProvider{
		config: config,
	}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	err := addZone(fqdn, d.config.TTL, "TXT", value)
	return err
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	remZone(fqdn)
	return nil
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// Thanks: https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go
func encode(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded)
}

func decode(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	return privateKey
}

func loadMyUser() *MyUser {
	// check if user exits or rego new user
	if _, err := os.Stat("certs/server.key"); os.IsNotExist(err) {
		// Create a user. New accounts need an email and private key to start.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		// encode key into strings
		encPriv := encode(privateKey)
		// save the private key
		err = os.WriteFile("certs/server.key", []byte(encPriv), 400)
		if err != nil {
			log.Fatal(err)
		}
	}

	privateKey, err := os.ReadFile("certs/server.key")
	if err != nil {
		log.Fatal(err)
	}

	// we need to see whether there is an appropriate registration.Resource
	// json file we can import and set below
	myUser := MyUser{
		Email: os.Getenv("LETS_ENCRYPT"),
		key:   decode(string([]byte(privateKey))),
	}

	return &myUser
}

func StartLetsEncrypt() {
	myUser := loadMyUser()
	config := lego.NewConfig(myUser)

	if os.Getenv("LE_ENV") == "staging" {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		config.Certificate.KeyType = certcrypto.RSA2048
	} else if (os.Getenv("LE_ENV") == "dev") {
		config.CADirURL = "http://127.0.0.1:4001/directory"
		config.Certificate.KeyType = certcrypto.RSA2048
	}

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	knaryDNS, err := NewDNSProvider()
	if err != nil {
		log.Fatal(err)
	}

	client.Challenge.SetDNS01Provider(knaryDNS)

	// if user exists, add rego details to struct
	// TODO currently as myUser.Registration is always empty at this point
	ereg, err := client.Registration.QueryRegistration()
	if err == nil {
		myUser.Registration = ereg
	} else {
		// if not, create new user
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatal(err)
		}
		// to fix the issue above
		// we need to save this information to a JSON file
		// and load it into MyUser when we load the private key and email address
		myUser.Registration = reg
	}

	var domainArray []string
	domainArray = append(domainArray, "*."+os.Getenv("CANARY_DOMAIN"))

	if os.Getenv("BURP_DOMAIN") != "" {
		domainArray = append(domainArray, "*."+os.Getenv("BURP_DOMAIN"))
	}

	request := certificate.ObtainRequest{
		Domains: domainArray,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// apparently we can renew like this:
	// client.Certificate.Renew(certRes certificate.Resource, bundle bool, mustStaple bool, preferredChain string)
	// we should do this in our TLS certificate daily check but when the certificate is ~20 days from expiry and
	// raise any issues in the renewal to our chans

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.

	// &certificate.Resource{Domain:"sam.ooo", CertURL:"https://acme-staging-v02.api.letsencrypt.org/acme/cert/fae516b4d8d5f2d5175a71e43fa9b957fb65", CertStableURL:"https://acme-staging-v02.api.letsencrypt.org/acme/cert/fae516b4d8d5f2d5175a71e43fa9b957fb65", PrivateKey:[]uint8{}
	// }, Certificate:[]uint8{}
	// }, IssuerCertificate:[]uint8{}
	// CSR:[]uint8(nil)
	fmt.Printf("%#v\n", certificates)


	certsStorage := cmd.NewCertificatesStorage()
	certsStorage.SaveResource(certificates)

	// ... all done.
}
