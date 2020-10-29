package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/jcmturner/pki/ca"
	"github.com/jcmturner/pki/certificate"
	"github.com/jcmturner/pki/csr"
)

func main() {
	caKeyPath := os.Getenv("CA_KEY")
	caCertPath := os.Getenv("CA_CERT")

	caKeyFile, err := os.Open(caKeyPath)
	if err != nil {
		log.Fatalf("error openning CA key: %v\n", err)
	}
	caCertFile, err := os.Open(caCertPath)
	if err != nil {
		log.Fatalf("error openning CA cert: %v\n", err)
	}
	caKeyBytes, err := ioutil.ReadAll(caKeyFile)
	if err != nil {
		log.Fatalf("error reading CA key: %v\n", err)
	}
	caCertBytes, err := ioutil.ReadAll(caCertFile)
	if err != nil {
		log.Fatalf("error reading CA cert: %v\n", err)
	}
	caCert, caKey, err := certificate.Load(caCertBytes, caKeyBytes, "")
	if err != nil {
		log.Fatalf("error loadinng the CA key/certificate: %v\n", err)
	}

	// Certificate generation and sign
	subj := pkix.Name{
		CommonName:   "jtserver.jtlan.co.uk",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	r, key, err := csr.New(subj, []string{"jtserver.jtlan.co.uk"}, rand.Reader)
	if err != nil {
		log.Fatalf("error creating CSR: %v\n", err)
	}
	crt, err := ca.Sign(r, caCert, caKey, time.Hour*24*365*10, rand.Reader)
	if err != nil {
		log.Fatalf("error signing cert: %v\n", err)
	}
	err = ioutil.WriteFile("/Users/turnerj/jtserver.jtlan.co.uk.pem", certificate.PEMEncode(crt), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/jtserver.jtlan.co.uk.key", certificate.PEMEncodeRSAPrivateKey(key), 0600)
	if err != nil {
		panic(err.Error())
	}
}
