package certificate

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

func PEMEncodeRSAPrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
}

func PEMEncode(crt *x509.Certificate) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		},
	)
}

// Load certificate and key from PEM encoded bytes
func Load(cert, key []byte, passphrase string) (CAcrt *x509.Certificate, CAkey *rsa.PrivateKey, err error) {
	// CA Certificate
	pemBlock, _ := pem.Decode(cert)
	if pemBlock == nil {
		err = errors.New("could not decode certificate bytes")
		return
	}
	CAcrt, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return
	}

	// CA private key
	pemBlock, _ = pem.Decode(key)
	if pemBlock == nil {
		err = errors.New("could not decode key bytes")
		return
	}
	der := pemBlock.Bytes
	if x509.IsEncryptedPEMBlock(pemBlock) {
		der, err = x509.DecryptPEMBlock(pemBlock, []byte(passphrase))
		if err != nil {
			return
		}
	}
	CAkey, err = x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return
	}
	return
}

func WriteCert(crt *x509.Certificate, w io.Writer) error {
	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
}

func WriteKey(key *rsa.PrivateKey, w io.Writer) error {
	return pem.Encode(w, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func WriteCertFile(crt *x509.Certificate, out string) error {
	certOut, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("could not create certificate file: %v", err)
	}
	err = WriteCert(crt, certOut)
	if err != nil {
		return fmt.Errorf("failed to write certificate data: %v", err)
	}
	err = certOut.Close()
	if err != nil {
		return fmt.Errorf("could not close certificate file: %v", err)
	}
	return nil
}

func WriteKeyFile(key *rsa.PrivateKey, out string) error {
	keyOut, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("could not create key file: %v", err)
	}
	err = WriteKey(key, keyOut)
	if err != nil {
		return fmt.Errorf("failed to write key data: %v", err)
	}
	err = keyOut.Close()
	if err != nil {
		return fmt.Errorf("could not close key file: %v", err)
	}
	return nil
}
