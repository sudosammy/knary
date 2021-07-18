package libknary

import (
	"time"
	"log"
	"strconv"
	"os"

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
			log.Fatal(err)
		}
		return reg
}

func needRenewal(days int) bool {
	
	certsStorage := cmd.NewCertificatesStorage()

	certificates, err := certsStorage.ReadCertificate(getDomains()[0], ".crt")
	if err != nil {
		log.Fatalf("Error while loading the certificate for domain \t%v", err)
	}

	x509Cert := certificates[0]

	if x509Cert.IsCA {
		log.Fatalf("Domain certificate bundle starts with a CA certificate...")
	}

	if days >= 0 {
		notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
		if notAfter > days {
			log.Printf("Domain certificate expires in %d days, the number of days defined to perform the renewal is %d: no renewal.", notAfter, days)
			return false
		}
	}

	return true
}

func renewLetsEncrypt(days int) {
	logger("INFO", "TLS certificate expires in "+strconv.Itoa(days)+" days. Attempting Let's Encrypt certificate renewal.")

	// apparently we can renew like this:
	// client.Certificate.Renew(certRes certificate.Resource, bundle bool, mustStaple bool, preferredChain string)
	// we should do this in our TLS certificate daily check but when the certificate is ~20 days from expiry and
	// raise any issues in the renewal to our chans

	// TEST archive move
	//certsStorage.MoveToArchive("*.sam.ooo")

}