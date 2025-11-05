package libknary

import (
	"crypto"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	cmd "github.com/sudosammy/knary/v3/libknary/lego"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	var confTTL int
	var confTimeout time.Duration
	var confPoll time.Duration

	if value, ok := os.LookupEnv("CERTBOT_TTL"); ok {
		confTTL, _ = strconv.Atoi(value)
	} else {
		confTTL = 120
	}

	if value, ok := os.LookupEnv("CERTBOT_PROPAGATION_TIMEOUT"); ok {
		timeVal, _ := strconv.Atoi(value)
		confTimeout = time.Duration(timeVal) * time.Second
	} else {
		confTimeout = 60 * time.Second
	}

	if value, ok := os.LookupEnv("CERTBOT_POLLING_INTERVAL"); ok {
		timeVal, _ := strconv.Atoi(value)
		confPoll = time.Duration(timeVal) * time.Second
	} else {
		confPoll = 2 * time.Second
	}

	return &Config{
		TTL:                confTTL,
		PropagationTimeout: confTimeout,
		PollingInterval:    confPoll,
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

func StartLetsEncrypt() {
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

	if os.Getenv("DNS_RESOLVER") != "" {
		client.Challenge.SetDNS01Provider(knaryDNS, dns01.AddRecursiveNameservers([]string{os.Getenv("DNS_RESOLVER")}))
	} else {
		client.Challenge.SetDNS01Provider(knaryDNS)
	}

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
	firstDomain := GetFirstDomain()

	// should only request certs if currently none exist
	if fileExists(certsStorage.GetFileName("*."+firstDomain, ".key")) &&
		fileExists(certsStorage.GetFileName("*."+firstDomain, ".crt")) {

		if os.Getenv("DEBUG") == "true" {
			Printy("TLS private key found: "+certsStorage.GetFileName("*."+firstDomain, ".key"), 3)
			Printy("TLS certificate found: "+certsStorage.GetFileName("*."+firstDomain, ".crt"), 3)
		}

		// Set TLS_CRT and TLS_KEY to our LE generated certs
		os.Setenv("TLS_CRT", filepath.Join(cmd.GetCertPath(), cmd.SanitizedDomain("*."+firstDomain)+".crt"))
		os.Setenv("TLS_KEY", filepath.Join(cmd.GetCertPath(), cmd.SanitizedDomain("*."+firstDomain)+".key"))

		// Check if certificate includes all required domains
		allDomainsPresent, missingDomains := checkCertificateDomains()
		if !allDomainsPresent {
			msg := "Certificate is missing required domains. Requesting new certificate with all domains."
			Printy(msg, 3)
			logger("INFO", msg)
			for _, domain := range missingDomains {
				Printy("Missing: "+domain, 3)
				logger("INFO", "Missing domain: "+domain)
			}
			go sendMsg(":lock: " + msg)
			// Continue to request new certificate instead of returning
		} else {
			return
		}
	}

	if os.Getenv("DEBUG") == "true" {
		Printy("No existing certificates found at:", 3)
		Printy(certsStorage.GetFileName("*."+firstDomain, ".key"), 2)
		Printy(certsStorage.GetFileName("*."+firstDomain, ".crt"), 2)
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

	// Set TLS_CRT and TLS_KEY to our LE generated certs
	os.Setenv("TLS_CRT", filepath.Join(cmd.GetCertPath(), cmd.SanitizedDomain("*."+firstDomain)+".crt"))
	os.Setenv("TLS_KEY", filepath.Join(cmd.GetCertPath(), cmd.SanitizedDomain("*."+firstDomain)+".key"))
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

	//certDomains := getDomainsForCert()
	certsStorage := cmd.NewCertificatesStorage()

	var privateKey crypto.PrivateKey

	keyBytes, errR := certsStorage.ReadFile("*."+GetFirstDomain(), ".key")
	if errR != nil {
		renewError(errR.Error())
	}

	privateKey, errR = certcrypto.ParsePEMPrivateKey(keyBytes)
	if errR != nil {
		renewError(errR.Error())
	}

	pemBundle, errR := certsStorage.ReadFile("*."+GetFirstDomain(), ".pem")
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

	// Use getDomainsForCert() to ensure all current domains are included
	// This allows adding new domains (like REVERSE_PROXY_DOMAIN) to existing certs
	query := certificate.ObtainRequest{
		Domains:    getDomainsForCert(),
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
	err = certsStorage.MoveToArchive("*." + GetFirstDomain())
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
