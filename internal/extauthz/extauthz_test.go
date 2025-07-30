package extauthz

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	rsaKeyID      string
	rsaPrivateKey *rsa.PrivateKey

	rsaPublicKey              *rsa.PublicKey
	rsaPublicKeyDER           []byte
	rsaPublicKeyPEMURLEncoded string

	x509CertPEMURLEncoded string
)

var urlEncodedInvalidCert = url.QueryEscape(`-----BEGIN CERTIFICATE-----
bla blubb
-----END CERTIFICATE-----`)

func createX509CertDER(notBefore, notAfter time.Time) ([]byte, error) {
	// create the x509 certificate
	certX509 := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"KMS, Inc"},
		},
		EmailAddresses: []string{"me@minime.com"},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &certX509, &certX509, rsaPublicKey, rsaPrivateKey)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

func createURLEncodedPEMCert(notBefore, notAfter time.Time) (string, error) {
	// create the x509 certificate and sign it
	certDER, err := createX509CertDER(notBefore, notAfter)
	if err != nil {
		return "", err
	}
	// encode it to PEM
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
	// return the URL encoded PEM certificate
	return url.QueryEscape(certPEM), nil
}

func TestMain(m *testing.M) {
	// create an RSA key pair
	rsaKeyID = uuid.New().String()

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("could not generate RSA key: %s", err)
	}

	rsaPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		log.Fatalf("Error marshalling RSA private key: %s", err)
	}

	_ = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: rsaPrivateKeyDER,
	}))
	rsaPublicKey = &rsaPrivateKey.PublicKey

	rsaPublicKeyDER, err = x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		log.Fatalf("Error marshalling RSA private key: %s", err)
	}

	_ = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rsaPublicKeyDER,
	}))

	// create x509 certificates
	x509CertPEMURLEncoded, err = createURLEncodedPEMCert(time.Now(), time.Now().Add(5*time.Minute))
	if err != nil {
		log.Fatalf("Error creating x509 certificate: %s", err)
	}

	// run the tests
	os.Exit(m.Run())
}
