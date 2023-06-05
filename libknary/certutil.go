package libknary

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	cmd "github.com/sudosammy/knary/libknary/lego"
)

// create domain list for certificates
func getDomainsForCert() []string {
	var domainArray []string
	var numDomains = 0

	for _, cdomain := range GetDomains() {
		domainArray = append(domainArray, "*."+cdomain)
		numDomains++

		if os.Getenv("DNS_SUBDOMAIN") != "" {
			domainArray = append(domainArray, "*."+os.Getenv("DNS_SUBDOMAIN")+"."+cdomain)
			numDomains++
		}
	}

	if os.Getenv("BURP_DOMAIN") != "" {
		domainArray = append(domainArray, "*."+os.Getenv("BURP_DOMAIN"))
		numDomains++
	}

	if os.Getenv("REVERSE_PROXY_DOMAIN") != "" {
		domainArray = append(domainArray, "*."+os.Getenv("REVERSE_PROXY_DOMAIN"))
		numDomains++
	}

	if os.Getenv("DEBUG") == "true" {
		Printy("Domains for SAN certificate: "+strconv.Itoa(numDomains), 3)
	}

	if numDomains > 100 {
		msg := "Too many domains! Let's Encrypt only supports SAN certificates containing 100 domains & subdomains. Your configuration currently has: " + strconv.Itoa(numDomains) + ". This may be due to configuring DNS_SUBDOMAIN which will double the number of SAN entries per CANARY_DOMAIN."
		logger("ERROR", msg)
		GiveHead(2)
		log.Fatal(msg)
	}
	return domainArray
}

func loadMyUser() *cmd.Account {
	accountStorage := cmd.NewAccountsStorage()

	privateKey := accountStorage.GetPrivateKey(certcrypto.EC384)
	//privateKey := accountStorage.GetPrivateKey(certcrypto.RSA2048)

	var account *cmd.Account
	if accountStorage.ExistsAccountFilePath() {
		account = accountStorage.LoadAccount(privateKey)
	} else {
		account = &cmd.Account{Email: accountStorage.GetUserID(), Key: privateKey}
	}

	return account
}

func registerAccount(client *lego.Client) *registration.Resource {
	// cmd.Account will just have our email address + private key in it, so we create new user
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}
	return reg
}

func needRenewal(days int) (bool, int) {
	certName := strings.TrimSuffix(filepath.Base(os.Getenv("TLS_CRT")), filepath.Ext(os.Getenv("TLS_CRT")))
	certExt := filepath.Ext(os.Getenv("TLS_CRT"))

	certsStorage := cmd.NewCertificatesStorage()
	certificates, err := certsStorage.ReadCertificate(certName, certExt)
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	x509Cert := certificates[0]
	// if x509Cert.IsCA {
	// 	Printy("Domain certificate bundle starts with a CA certificate.", 2)
	// 	logger("ERROR", "Cannot check for certificate expiry due to the domains certificate bundle (.crt) starts with a CA certificate.")
	// 	return false, 0
	// }

	notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)

	if days >= 0 && notAfter > days {
		return false, notAfter
	}
	return true, notAfter
}
