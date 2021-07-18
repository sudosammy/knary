package libknary

import (
	// "crypto"
	// "crypto/elliptic"
	// "crypto/rand"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"time"

	cmd "github.com/sudosammy/knary/libknary/lego"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/registration"
)

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

func loadMyUser() *cmd.Account {
	accountStorage := cmd.NewAccountsStorage()

	//privateKey := accountStorage.GetPrivateKey(certcrypto.EC384)
	privateKey := accountStorage.GetPrivateKey(certcrypto.RSA2048)

	var account *cmd.Account
	if accountStorage.ExistsAccountFilePath() {
		account = accountStorage.LoadAccount(privateKey)
	} else {
		account = &cmd.Account{Email: accountStorage.GetUserID(), Key: privateKey}
	}

	return &*account
}

func StartLetsEncrypt() string {

	myUser := loadMyUser()
	config := lego.NewConfig(myUser)

	if os.Getenv("LE_ENV") == "staging" {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	} else if (os.Getenv("LE_ENV") == "dev") {
		config.CADirURL = "http://127.0.0.1:4001/directory"
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

	// if we're an existing user, loadMyUser would have populated cmd.Account with our Registration details
	currentReg, err := client.Registration.QueryRegistration()
	if err == nil {
		myUser.Registration = currentReg

	} else {
		// if not, cmd.Account will just have our email address + private key in it, so we create new user
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatal(err)
		}
		myUser.Registration = reg

		// save these registration details to disk
		accountStorage := cmd.NewAccountsStorage()
		if err := accountStorage.Save(myUser); err != nil {
			log.Fatal(err)
		}
	}

	var domainArray []string
	domainArray = append(domainArray, "*."+os.Getenv("CANARY_DOMAIN"))

	if os.Getenv("BURP_DOMAIN") != "" {
		domainArray = append(domainArray, "*."+os.Getenv("BURP_DOMAIN"))
	}

	// should only request certs if the current ones are old...
	certsStorage := cmd.NewCertificatesStorage()

	if certsStorage.ExistsFile(cmd.SanitizedDomain("*."+os.Getenv("CANARY_DOMAIN")),"key") &&
		certsStorage.ExistsFile(cmd.SanitizedDomain("*."+os.Getenv("CANARY_DOMAIN")),"crt") {
		// We have keys already, don't need new ones.
		return cmd.SanitizedDomain(os.Getenv("CANARY_DOMAIN"))
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

	// TEST archive move
	//certsStorage.MoveToArchive("*.sam.ooo")
	
	certsStorage.SaveResource(certificates)

	return cmd.SanitizedDomain(certificates.Domain)
}
