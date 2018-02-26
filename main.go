package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"time"
)

func main() {
	subj := pkix.Name{
		CommonName:   "JTNET-Root-CA-1",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	//SANs := []string{"host.test.com"}
	caCSR, cakey, err := csr(subj, []string{})
	if err != nil {
		panic(err.Error())
	}

	caCert, err := createCA(caCSR, cakey, time.Hour*24*365*20)

	// save the certificate
	//err = ioutil.WriteFile("/Users/turnerj/testca.crt", PEMEncodeCertificate(caCert), 0644)
	//if err != nil {
	//	panic(err.Error())
	//}

	subj = pkix.Name{
		CommonName:   "www2.host.co.uk",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	r, key, _ := csr(subj, []string{"git.host.co.uk"})
	crt, _ := signCSR(r, caCert, cakey, time.Hour*24)
	err = ioutil.WriteFile("/Users/turnerj/www.crt", PEMEncodeCertificate(crt), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/www.key", PEMEncodeRSAPrivateKey(key), 0644)
	if err != nil {
		panic(err.Error())
	}
}

// csr returns PEM encoded bytes for a CSR
func csr(subj pkix.Name, SANs []string) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	csrType, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return &x509.CertificateRequest{}, key, err
	}
	if err = csrType.CheckSignature(); err != nil {
		return &x509.CertificateRequest{}, key, err
	}
	return csrType, key, nil
}

func PEMEncodeCSR(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr.Raw,
		},
	)
}

func PEMEncodeRSAPrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
}

func PEMEncodeCertificate(crt *x509.Certificate) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		},
	)
}

// loadCert takes the certificate and key PEM encoded bytes
func loadCert(cert, key []byte, passphrase string) (CAcrt *x509.Certificate, CAkey *rsa.PrivateKey, err error) {
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

// loadCSR from PEM encoded bytes.
func loadCSR(b []byte) (csr *x509.CertificateRequest, err error) {
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

// signCSR
func signCSR(csr *x509.CertificateRequest, CAcrt *x509.Certificate, CAkey *rsa.PrivateKey, duration time.Duration) (*x509.Certificate, error) {
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
	crtRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, CAcrt, csr.PublicKey, CAkey)
	if err != nil {
		return &x509.Certificate{}, err
	}
	crt, err := x509.ParseCertificate(crtRaw)
	if err != nil {
		return &x509.Certificate{}, err
	}
	return crt, nil
}

// createCA returns the PEM bytes of a Certificate Authority
func createCA(csr *x509.CertificateRequest, key *rsa.PrivateKey, duration time.Duration) (*x509.Certificate, error) {
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
		IsCA:         true,
		SubjectKeyId: ski[:],
	}
	// create certificate from template and CA
	crtRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, &clientCRTTemplate, csr.PublicKey, key)
	if err != nil {
		return &x509.Certificate{}, err
	}
	crt, err := x509.ParseCertificate(crtRaw)
	if err != nil {
		return &x509.Certificate{}, err
	}
	return crt, nil
}
