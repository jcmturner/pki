package main

import (
	"crypto/rand"
	"flag"
	"io/ioutil"
	"log"
	"time"

	"github.com/jcmturner/pki/ca"
	"github.com/jcmturner/pki/certificate"
	"github.com/jcmturner/pki/csr"
)

func main() {
	cacertp := flag.String("cacert", "", "Path to the CA certificate file")
	cakeyp := flag.String("cakey", "", "Path to the CA private key file")
	csrp := flag.String("csr", "", "Path to the certificate signing request (CSR) file")
	d := flag.Duration("duration", time.Hour*24*365*2, "Expiration duration of the CA")
	flag.Parse()

	//Load the CSR
	b, err := ioutil.ReadFile(*csrp)
	if err != nil {
		log.Fatalf("could not read CSR file: %v", err)
	}
	csr, err := csr.Load(b)
	if err != nil {
		log.Fatalf("could not load CSR: %v", err)
	}

	cb, err := ioutil.ReadFile(*cacertp)
	if err != nil {
		log.Fatalf("could not read CA certificate file: %v", err)
	}
	kb, err := ioutil.ReadFile(*cakeyp)
	if err != nil {
		log.Fatalf("could not read CA key file: %v", err)
	}

	cacert, cakey, err := certificate.Load(cb, kb, "")
	if err != nil {
		log.Fatal(err)
	}

	cert, err := ca.Sign(csr, cacert, cakey, *d, rand.Reader)
	if err != nil {
		log.Fatalf("could not sign certificate: %v", err)
	}
	err = certificate.WriteCertFile(cert, "./"+csr.Subject.String()+".pem")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("certificate signed and written to: %s", "./"+csr.Subject.String()+".pem")
}
