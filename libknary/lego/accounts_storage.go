package cmd

// Many thanks to the original authors of this code
// https://github.com/go-acme/lego/blob/83c626d9a1889fa499bc9c97bc2fdea965307002/cmd/accounts_storage.go

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
)

type AccountsStorage struct {
	userID          string
	accountFilePath string
	keyFilePath     string
}

// NewAccountsStorage Creates a new AccountsStorage.
func NewAccountsStorage() *AccountsStorage {
	email := os.Getenv("LETS_ENCRYPT")
	return &AccountsStorage{
		userID:          email,
		accountFilePath: filepath.Join(baseCertificatesFolderName, "account.json"),
		keyFilePath:     filepath.Join(baseCertificatesFolderName, "knary.key"),
	}
}

func (s *AccountsStorage) ExistsAccountFilePath() bool {
	accountFile := s.accountFilePath
	if _, err := os.Stat(accountFile); os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatal(err)
	}
	return true
}

func (s *AccountsStorage) GetUserID() string {
	return s.userID
}

func (s *AccountsStorage) Save(account *Account) error {
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(s.accountFilePath, jsonBytes, 0o600)
}

func (s *AccountsStorage) LoadAccount(privateKey crypto.PrivateKey) *Account {
	fileBytes, err := ioutil.ReadFile(s.accountFilePath)
	if err != nil {
		log.Fatalf("Could not load file for account %s: %v", s.userID, err)
	}

	var account Account
	err = json.Unmarshal(fileBytes, &account)
	if err != nil {
		log.Fatalf("Could not parse file for account %s: %v", s.userID, err)
	}

	account.Key = privateKey

	if account.Registration == nil || account.Registration.Body.Status == "" {
		reg, err := tryRecoverRegistration(privateKey)
		if err != nil {
			log.Fatalf("Could not load account for %s. Registration is nil: %#v", s.userID, err)
		}

		account.Registration = reg
		err = s.Save(&account)
		if err != nil {
			log.Fatalf("Could not save account for %s. Registration is nil: %#v", s.userID, err)
		}
	}

	return &account
}

func (s *AccountsStorage) GetPrivateKey(keyType certcrypto.KeyType) crypto.PrivateKey {
	accKeyPath := s.keyFilePath

	if _, err := os.Stat(accKeyPath); os.IsNotExist(err) {
		log.Printf("No key found for account %s. Generating a %s key.", s.userID, keyType)

		privateKey, err := generatePrivateKey(accKeyPath, keyType)
		if err != nil {
			log.Fatalf("Could not generate RSA private account key for account %s: %v", s.userID, err)
		}

		log.Printf("Saved key to %s", accKeyPath)
		return privateKey
	}

	privateKey, err := loadPrivateKey(accKeyPath)
	if err != nil {
		log.Fatalf("Could not load RSA private key from file %s: %v", accKeyPath, err)
	}

	return privateKey
}

func generatePrivateKey(file string, keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer certOut.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(certOut, pemKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

func tryRecoverRegistration(privateKey crypto.PrivateKey) (*registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	config := lego.NewConfig(&Account{Key: privateKey})

	if os.Getenv("LE_ENV") == "staging" {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	} else if os.Getenv("LE_ENV") == "dev" {
		config.CADirURL = "http://127.0.0.1:4001/directory"
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, err
	}
	return reg, nil
}
