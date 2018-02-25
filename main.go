package pki

import (
	"bytes"
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
	cakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err.Error())
	}
	//cakeyPEM := pem.EncodeToMemory(
	//	&pem.Block{
	//		Type: "RSA PRIVATE KEY",
	//		Bytes: x509.MarshalPKCS1PrivateKey(cakey),
	//	},
	//)

	subj := pkix.Name{
		CommonName:   "JTNET-Root-CA-1",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	//SANs := []string{"host.test.com"}
	caCsrPEM, err := csr(subj, []string{})
	if err != nil {
		panic(err.Error())
	}
	caCSR, err := loadCSR(caCsrPEM)
	if err != nil {
		panic(err.Error())
	}

	caBytes, err := createCA(caCSR, cakey, time.Hour*24*365*20)
	//caCert, _, err := loadCert(caBytes, cakeyPEM, "")

	// save the certificate
	err = ioutil.WriteFile("/Users/turnerj/testca.crt", caBytes, 0644)
	if err != nil {
		panic(err.Error())
	}
}

// csr returns PEM encoded bytes for a CSR
func csr(subj pkix.Name, SANs []string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return []byte{}, err
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
		return []byte{}, err
	}
	template := x509.CertificateRequest{
		Version:            3,
		RawSubject:         asn1Subj,
		DNSNames:           SANs,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var buf bytes.Buffer
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return buf.Bytes(), nil
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
func signCSR(csr *x509.CertificateRequest, CAcrt *x509.Certificate, CAkey **rsa.PrivateKey, duration time.Duration) ([]byte, error) {
	snb := make([]byte, 20)
	_, err := rand.Read(snb)
	if err != nil {
		return []byte{}, err
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
		return []byte{}, err
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: crtRaw})
	return buf.Bytes(), nil
}

// createCA returns the PEM bytes of a Certificate Authority
func createCA(csr *x509.CertificateRequest, key *rsa.PrivateKey, duration time.Duration) ([]byte, error) {
	pubBytes := x509.MarshalPKCS1PublicKey(csr.PublicKey.(*rsa.PublicKey))
	ski := sha1.Sum(pubBytes)
	snb := make([]byte, 20)
	_, err := rand.Read(snb)
	if err != nil {
		return []byte{}, err
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
		return []byte{}, err
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: crtRaw})
	return buf.Bytes(), nil
}
