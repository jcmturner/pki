package csr

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
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

func Write(csr *x509.CertificateRequest, w io.Writer) error {
	return pem.Encode(w, &pem.Block{
		Type:  pemHeader,
		Bytes: csr.Raw,
	})
}

func WriteFile(csr *x509.CertificateRequest, out string) error {
	csrOut, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("could not create CSR file: %v", err)
	}
	err = Write(csr, csrOut)
	if err != nil {
		return fmt.Errorf("failed to write CSR data: %v", err)
	}
	err = csrOut.Close()
	if err != nil {
		return fmt.Errorf("could not close CSR file: %v", err)
	}
	return nil
}
