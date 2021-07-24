package libknary

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	cmd "github.com/sudosammy/knary/libknary/lego"
)

// create domain list for certificates
func getDomains() []string {
	var domainArray []string
	domainArray = append(domainArray, "*."+os.Getenv("CANARY_DOMAIN"))

	if os.Getenv("BURP_DOMAIN") != "" {
		domainArray = append(domainArray, "*."+os.Getenv("BURP_DOMAIN"))
	}

	if os.Getenv("DNS_SUBDOMAIN") != "" {
		domainArray = append(domainArray, "*."+os.Getenv("DNS_SUBDOMAIN"))
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

	return &*account
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
