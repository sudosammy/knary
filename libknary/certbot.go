package libknary

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/platform/config/env"
	cmd "github.com/sudosammy/knary/libknary/lego"
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

	if err == nil && currentReg.Body.Status != "valid" {
		Printy("Found the Let's Encrypt user, but apparently the registration is not valid. We'll try re-registering...", 2)
		
		myUser.Registration = registerAccount(client)
		
		// save these registration details to disk
		accountStorage := cmd.NewAccountsStorage()
		if err := accountStorage.Save(myUser); err != nil {
			log.Fatal(err)
		}

	} else if err == nil && currentReg.Body.Status == "valid" {
		myUser.Registration = currentReg

	} else {
		myUser.Registration = registerAccount(client)
		
		// save these registration details to disk
		accountStorage := cmd.NewAccountsStorage()
		if err := accountStorage.Save(myUser); err != nil {
			log.Fatal(err)
		}
	}

	certsStorage := cmd.NewCertificatesStorage()

	// should only request certs if currently none exist
	if fileExists(certsStorage.GetFileName(getDomains()[0], "key")) &&
		fileExists(certsStorage.GetFileName(getDomains()[0], "crt")) {
		
		return cmd.SanitizedDomain(getDomains()[0])
	}

	request := certificate.ObtainRequest{
		Domains: getDomains(),
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}
	
	certsStorage.SaveResource(certificates)
	return cmd.SanitizedDomain(certificates.Domain)
}
