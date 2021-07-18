package libknary

import (
	"errors"
	"log"
	"os"
	"time"
	"crypto"

	"github.com/go-acme/lego/v4/certcrypto"
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
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	knaryDNS, err := NewDNSProvider()
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
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
			logger("ERROR", err.Error())
			GiveHead(2)
			log.Fatal(err)
		}

	} else if err == nil && currentReg.Body.Status == "valid" {
		myUser.Registration = currentReg

	} else {
		myUser.Registration = registerAccount(client)
		
		// save these registration details to disk
		accountStorage := cmd.NewAccountsStorage()
		if err := accountStorage.Save(myUser); err != nil {
			logger("ERROR", err.Error())
			GiveHead(2)
			log.Fatal(err)
		}
	}

	certsStorage := cmd.NewCertificatesStorage()

	// should only request certs if currently none exist
	if fileExists(certsStorage.GetFileName(getDomains()[0], ".key")) &&
		fileExists(certsStorage.GetFileName(getDomains()[0], ".crt")) {
		
		if os.Getenv("DEBUG") == "true" {
			Printy("TLS private key found: " + certsStorage.GetFileName(getDomains()[0], ".key"), 3)
			Printy("TLS certificate found: " + certsStorage.GetFileName(getDomains()[0], ".crt"), 3)
		}
		return cmd.SanitizedDomain(getDomains()[0])
	}

	if os.Getenv("DEBUG") == "true" {
		Printy("No existing certificates found at:", 3)
		Printy(certsStorage.GetFileName(getDomains()[0], ".key"), 2)
		Printy(certsStorage.GetFileName(getDomains()[0], ".crt"), 2)
		Printy("Let's Encrypt ourselves some new ones!", 3)
	}

	request := certificate.ObtainRequest{
		Domains: getDomains(),
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}
	
	certsStorage.SaveResource(certificates)
	return cmd.SanitizedDomain(certificates.Domain)
}

func renewLetsEncrypt() {
	Printy("Attempting Let's Encrypt renewal", 3)
	logger("INFO", "Attempting Let's Encrypt certificate renewal.")
	go sendMsg(":lock: Attempting renewal of the Let's Encrypt certificate. I'll let you know how I go.")

	myUser := loadMyUser()
	config := lego.NewConfig(myUser)

	if os.Getenv("LE_ENV") == "staging" {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	} else if (os.Getenv("LE_ENV") == "dev") {
		config.CADirURL = "http://127.0.0.1:4001/directory"
	}

	client, err := lego.NewClient(config)
	if err != nil {
		go sendMsg(":warning: " + err.Error() + " :warning:")
		go sendMsg("knary is shutting down because of this error :(")
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	certDomains := getDomains()
	certsStorage := cmd.NewCertificatesStorage()

	var privateKey crypto.PrivateKey
	
	keyBytes, errR := certsStorage.ReadFile(certDomains[0], ".key")
	if errR != nil {
		go sendMsg(":warning: " + errR.Error() + " :warning:")
		go sendMsg("knary is shutting down because of this error :(")
		logger("ERROR", errR.Error())
		GiveHead(2)
		log.Fatal(errR)
	}

	privateKey, errR = certcrypto.ParsePEMPrivateKey(keyBytes)
	if errR != nil {
		go sendMsg(":warning: " + errR.Error() + " :warning:")
		go sendMsg("knary is shutting down because of this error :(")
		logger("ERROR", errR.Error())
		GiveHead(2)
		log.Fatal(errR)
	}
	
	request := certificate.ObtainRequest {
		Domains:        certDomains,
		Bundle:         false,
		PrivateKey:     privateKey,
		MustStaple:     false,
		PreferredChain: "",
	}
	certRes, err := client.Certificate.Obtain(request)
	if err != nil {
		go sendMsg(":warning: " + err.Error() + " :warning:")
		go sendMsg("knary is shutting down because of this error :(")
		log.Fatal(err)
	}

	// move old certificates to archive folder
	if os.Getenv("DEBUG") == "true" {
		Printy("Archiving old certificates", 3)
	}
	certsStorage.MoveToArchive(certDomains[0])

	certsStorage.SaveResource(certRes)
	msg := "Certificate successfully renewed!"
	go sendMsg(":lock: " + msg)
	logger("INFO", msg)
	Printy(msg, 3)
}
