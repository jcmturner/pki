package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	der, err := x509.DecryptPEMBlock(pemBlock, []byte(passphrase))
	if err != nil {
		return
	}
	CAkey, err = x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return
	}
	return
}
