package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"time"
)

// New generates a new Certificate Authority
func New(csr *x509.CertificateRequest, key *rsa.PrivateKey, duration time.Duration, rnd io.Reader) (*x509.Certificate, error) {
	pubBytes := x509.MarshalPKCS1PublicKey(csr.PublicKey.(*rsa.PublicKey))
	ski := sha1.Sum(pubBytes)
	snb := make([]byte, 20)
	_, err := rand.Read(snb)
	if err != nil {
		return &x509.Certificate{}, err
	}
	sn := int64(binary.BigEndian.Uint64(snb))
	clientCRTTemplate := x509.Certificate{
		Version:            csr.Version,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber:          big.NewInt(sn),
		Issuer:                csr.Subject,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski[:],
	}
	// create certificate from template and CA
	crtRaw, err := x509.CreateCertificate(rnd, &clientCRTTemplate, &clientCRTTemplate, csr.PublicKey, key)
	if err != nil {
		return &x509.Certificate{}, err
	}
	crt, err := x509.ParseCertificate(crtRaw)
	if err != nil {
		return &x509.Certificate{}, err
	}
	return crt, nil
}

// Sign the CSR
func Sign(csr *x509.CertificateRequest, CAcrt *x509.Certificate, CAkey *rsa.PrivateKey, duration time.Duration, rnd io.Reader) (*x509.Certificate, error) {
	snb := make([]byte, 20)
	_, err := rand.Read(snb)
	if err != nil {
		return &x509.Certificate{}, err
	}
	sn := int64(binary.BigEndian.Uint64(snb))
	clientCRTTemplate := x509.Certificate{
		Version:            csr.Version,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(sn),
		Issuer:       CAcrt.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(duration),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IsCA:         false,
	}
	// create certificate from template and CA
	crtRaw, err := x509.CreateCertificate(rnd, &clientCRTTemplate, CAcrt, csr.PublicKey, CAkey)
	if err != nil {
		return &x509.Certificate{}, err
	}
	crt, err := x509.ParseCertificate(crtRaw)
	if err != nil {
		return &x509.Certificate{}, err
	}
	return crt, nil
}
