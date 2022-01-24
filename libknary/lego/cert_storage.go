package cmd

// Many thanks to the original authors of this code
// https://github.com/go-acme/lego/blob/83c626d9a1889fa499bc9c97bc2fdea965307002/cmd/certs_storage.go

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/log"
	"golang.org/x/net/idna"
)

// GetCertPath():
//     /knary/certs/
//                └── root certificates directory
//
// archive file path:
//     /knary/certs/archives/
//                    └── archived certificates directory
//
func GetCertPath() string {
	var certFolderName string
	var certPath string

	if os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "" {
		// this is the default LE config
		certPath = "certs" // put LE certs in ./certs/* dir. if it doesn't exist, it'll be created by StartLetsEncrypt()
	} else {
		certPath = os.Getenv("TLS_CRT")
	}

	if !filepath.IsAbs(certPath) {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf(err.Error())
		}

		path, err := filepath.Abs(filepath.Join(pwd, certPath))
		if err != nil {
			log.Fatalf(err.Error())
		}

		certFolderName = path
	} else {
		certFolderName = filepath.Dir(certPath)
	}

	return certFolderName
}

type CertificatesStorage struct {
	rootPath    string
	archivePath string
	pem         bool
}

// NewCertificatesStorage create a new certificates storage.
func NewCertificatesStorage() *CertificatesStorage {
	return &CertificatesStorage{
		rootPath:    GetCertPath(),
		archivePath: filepath.Join(GetCertPath(), "archives"),
		pem:         true,
	}
}

func (s *CertificatesStorage) SaveResource(certRes *certificate.Resource) {
	domain := certRes.Domain

	// We store the certificate, private key and metadata in different files
	// as web servers would not be able to work with a combined file.
	err := s.WriteFile(domain, ".crt", certRes.Certificate)
	if err != nil {
		log.Fatalf("Unable to save Certificate for domain %s\n\t%v", domain, err)
	}

	if certRes.IssuerCertificate != nil {
		err = s.WriteFile(domain, ".issuer.crt", certRes.IssuerCertificate)
		if err != nil {
			log.Fatalf("Unable to save IssuerCertificate for domain %s\n\t%v", domain, err)
		}
	}

	if certRes.PrivateKey != nil {
		// if we were given a CSR, we don't know the private key
		err = s.WriteFile(domain, ".key", certRes.PrivateKey)
		if err != nil {
			log.Fatalf("Unable to save PrivateKey for domain %s\n\t%v", domain, err)
		}

		if s.pem {
			err = s.WriteFile(domain, ".pem", bytes.Join([][]byte{certRes.Certificate, certRes.PrivateKey}, nil))
			if err != nil {
				log.Fatalf("Unable to save Certificate and PrivateKey in .pem for domain %s\n\t%v", domain, err)
			}
		}
	} else if s.pem {
		// we don't have the private key; can't write the .pem file
		log.Fatalf("Unable to save pem without private key for domain %s\n\t%v; are you using a CSR?", domain, err)
	}

	jsonBytes, err := json.MarshalIndent(certRes, "", "\t")
	if err != nil {
		log.Fatalf("Unable to marshal CertResource for domain %s\n\t%v", domain, err)
	}

	err = s.WriteFile(domain, ".json", jsonBytes)
	if err != nil {
		log.Fatalf("Unable to save CertResource for domain %s\n\t%v", domain, err)
	}
}

func (s *CertificatesStorage) ReadResource(domain string) certificate.Resource {
	raw, err := s.ReadFile(domain, ".json")
	if err != nil {
		log.Fatalf("Error while loading the meta data for domain %s\n\t%v", domain, err)
	}

	var resource certificate.Resource
	if err = json.Unmarshal(raw, &resource); err != nil {
		log.Fatalf("Error while marshaling the meta data for domain %s\n\t%v", domain, err)
	}

	return resource
}

func (s *CertificatesStorage) ReadFile(domain, extension string) ([]byte, error) {
	return ioutil.ReadFile(s.GetFileName(domain, extension))
}

func (s *CertificatesStorage) GetFileName(domain, extension string) string {
	filename := SanitizedDomain(domain) + extension
	return filepath.Join(s.rootPath, filename)
}

func (s *CertificatesStorage) ReadCertificate(domain, extension string) ([]*x509.Certificate, error) {
	content, err := s.ReadFile(domain, extension)
	if err != nil {
		return nil, err
	}

	// The input may be a bundle or a single certificate.
	return certcrypto.ParsePEMBundle(content)
}

func (s *CertificatesStorage) WriteFile(domain, extension string, data []byte) error {
	baseFileName := SanitizedDomain(domain)
	filePath := filepath.Join(s.rootPath, baseFileName+extension)

	return ioutil.WriteFile(filePath, data, 0400)
}

func (s *CertificatesStorage) MoveToArchive(domain string) error {
	matches, err := filepath.Glob(filepath.Join(s.rootPath, SanitizedDomain(domain)+".*"))
	if err != nil {
		return err
	}

	for _, oldFile := range matches {
		date := strconv.FormatInt(time.Now().Unix(), 10)
		filename := date + "." + filepath.Base(oldFile)
		newFile := filepath.Join(s.archivePath, filename)

		err = os.Rename(oldFile, newFile)
		if err != nil {
			return err
		}
	}

	return nil
}

// sanitizedDomain Make sure no funny chars are in the cert names (like wildcards ;)).
func SanitizedDomain(domain string) string {
	safe, err := idna.ToASCII(strings.ReplaceAll(domain, "*", "_"))
	if err != nil {
		log.Fatal(err)
	}
	return safe
}
