package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"time"
)

const (
	keySize   = 2048
	pemHeader = "CERTIFICATE REQUEST"
)

// New creates a new CSR
func New(subj pkix.Name, SANs []string, rnd io.Reader) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rnd, keySize)
	if err != nil {
		return &x509.CertificateRequest{}, key, err
	}
	var cn bool
	for _, n := range SANs {
		if n == subj.CommonName {
			cn = true
			break
		}
	}
	if !cn {
		SANs = append(SANs, subj.CommonName)
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return &x509.CertificateRequest{}, key, err
	}
	template := x509.CertificateRequest{
		Version:            3,
		RawSubject:         asn1Subj,
		DNSNames:           SANs,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rnd, &template, key)
	csrType, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return &x509.CertificateRequest{}, key, err
	}
	if err = csrType.CheckSignature(); err != nil {
		return &x509.CertificateRequest{}, key, err
	}
	return csrType, key, nil
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

// Load CSR from PEM encoded bytes.
func Load(b []byte) (csr *x509.CertificateRequest, err error) {
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
		err = errors.New("could not decode certificate request bytes")
		return
	}
	csr, err = x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return
	}
	if err = csr.CheckSignature(); err != nil {
		return
	}
	return
}

// PEMEncode returns the PEM encoded bytes for the CSR
func PEMEncode(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  pemHeader,
			Bytes: csr.Raw,
		},
	)
}
