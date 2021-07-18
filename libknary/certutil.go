package libknary

import (
	"time"
	"log"
	"os"
	"strings"
	"path/filepath"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/go-acme/lego/v4/certcrypto"
	cmd "github.com/sudosammy/knary/libknary/lego"
)

// create domain list for certificates
func getDomains() []string {
	var domainArray []string
	domainArray = append(domainArray, "*."+os.Getenv("CANARY_DOMAIN"))

	if os.Getenv("BURP_DOMAIN") != "" {
		domainArray = append(domainArray, "*."+os.Getenv("BURP_DOMAIN"))
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
	certName := strings.TrimSuffix(os.Getenv("TLS_CRT"), filepath.Ext(os.Getenv("TLS_CRT")))
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

func renewLetsEncrypt() {
	logger("INFO", "Attempting Let's Encrypt certificate renewal.")

	// apparently we can renew like this:
	// client.Certificate.Renew(certRes certificate.Resource, bundle bool, mustStaple bool, preferredChain string)
	// we should do this in our TLS certificate daily check but when the certificate is ~20 days from expiry and
	// raise any issues in the renewal to our chans

	// TEST archive move
	//certsStorage.MoveToArchive("*.sam.ooo")

}