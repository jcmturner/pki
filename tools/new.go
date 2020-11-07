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

const (
	hostname   = "jtlaptop.jtlan.co.uk"
	outputdir  = "/home/turnerj/security"
	caKeyPath  = "/home/turnerj/security/jtca.key"
	caCertPath = "/home/turnerj/security/jtca.crt"
)

func main() {
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
		CommonName:   hostname,
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	r, key, err := csr.New(subj, []string{hostname}, rand.Reader)
	if err != nil {
		log.Fatalf("error creating CSR: %v\n", err)
	}
	crt, err := ca.Sign(r, caCert, caKey, time.Hour*24*365*10, rand.Reader)
	if err != nil {
		log.Fatalf("error signing cert: %v\n", err)
	}
	err = ioutil.WriteFile(outputdir+"/"+hostname+".pem", certificate.PEMEncode(crt), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile(outputdir+"/"+hostname+".key", certificate.PEMEncodeRSAPrivateKey(key), 0600)
	if err != nil {
		panic(err.Error())
	}
}
