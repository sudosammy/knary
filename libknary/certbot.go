package libknary

import (
	"crypto"
	"errors"
	"log"
	"os"
	"time"

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
	// check if folder structure is correct
	cmd.CreateFolderStructure()

	myUser := loadMyUser()
	config := lego.NewConfig(myUser)

	if os.Getenv("LE_ENV") == "staging" {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	} else if os.Getenv("LE_ENV") == "dev" {
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
	if fileExists(certsStorage.GetFileName("*."+GetFirstDomain(), ".key")) &&
		fileExists(certsStorage.GetFileName("*."+GetFirstDomain(), ".crt")) {

		if os.Getenv("DEBUG") == "true" {
			Printy("TLS private key found: "+certsStorage.GetFileName("*."+GetFirstDomain(), ".key"), 3)
			Printy("TLS certificate found: "+certsStorage.GetFileName("*."+GetFirstDomain(), ".crt"), 3)
		}
		return cmd.SanitizedDomain(GetFirstDomain())
	}

	if os.Getenv("DEBUG") == "true" {
		Printy("No existing certificates found at:", 3)
		Printy(certsStorage.GetFileName("*."+GetFirstDomain(), ".key"), 2)
		Printy(certsStorage.GetFileName("*."+GetFirstDomain(), ".crt"), 2)
		Printy("Let's Encrypt ourselves some new ones!", 3)
	}

	request := certificate.ObtainRequest{
		Domains: getDomainsForCert(),
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

func renewError(msg string) {
	go sendMsg(":warning: " + msg)
	go sendMsg(":warning: knary is shutting down because of this error :(")
	logger("ERROR", msg)
	GiveHead(2)
	log.Fatal(msg)
}

func renewLetsEncrypt() {
	Printy("Attempting Let's Encrypt renewal", 1)
	logger("INFO", "Attempting Let's Encrypt certificate renewal.")
	go sendMsg(":lock: Attempting renewal of the Let's Encrypt certificate. I'll let you know how I go.")

	myUser := loadMyUser()
	config := lego.NewConfig(myUser)

	if os.Getenv("LE_ENV") == "staging" {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	} else if os.Getenv("LE_ENV") == "dev" {
		config.CADirURL = "http://127.0.0.1:4001/directory"
	}

	client, err := lego.NewClient(config)
	if err != nil {
		renewError(err.Error())
	}

	knaryDNS, err := NewDNSProvider()
	if err != nil {
		renewError(err.Error())
	}
	client.Challenge.SetDNS01Provider(knaryDNS)

	certDomains := getDomainsForCert()
	certsStorage := cmd.NewCertificatesStorage()

	var privateKey crypto.PrivateKey

	keyBytes, errR := certsStorage.ReadFile(certDomains[0], ".key")
	if errR != nil {
		renewError(errR.Error())
	}

	privateKey, errR = certcrypto.ParsePEMPrivateKey(keyBytes)
	if errR != nil {
		renewError(errR.Error())
	}

	pemBundle, errR := certsStorage.ReadFile(certDomains[0], ".pem")
	if errR != nil {
		renewError(errR.Error())
	}

	certificates, errR := certcrypto.ParsePEMBundle(pemBundle)
	if errR != nil {
		renewError(errR.Error())
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		renewError("Certificate bundle starts with a CA certificate")
	}

	query := certificate.ObtainRequest{
		Domains:    certcrypto.ExtractDomains(x509Cert),
		Bundle:     true,
		PrivateKey: privateKey,
		MustStaple: false,
	}
	certRes, errR := client.Certificate.Obtain(query)
	if errR != nil {
		renewError(errR.Error())
	}

	// move old certificates to archive folder
	if os.Getenv("DEBUG") == "true" {
		Printy("Archiving old certificates", 3)
	}
	err = certsStorage.MoveToArchive(certDomains[0])
	if err != nil {
		msg := "There was an error moving the old certificates to the archive folder. Did you delete the folder? I'll overwrite the old certificates instead. See the log for more information."
		go sendMsg(":warning: " + msg)
		Printy(msg, 2)
		logger("WARNING", "Could not move certificates to archive: "+err.Error())
	}

	certsStorage.SaveResource(certRes)
	msg := "Certificate successfully renewed!"
	go sendMsg(":lock: " + msg)
	logger("INFO", msg)
	Printy(msg, 3)
}
