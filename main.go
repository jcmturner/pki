package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/jcmturner/pki/ca"
	"github.com/jcmturner/pki/cert"
	"github.com/jcmturner/pki/csr"
	"github.com/jcmturner/pki/kmsrand"
)

func main() {
	// KMS Random number reader
	rnd := kmsrand.Reader{
		KMSsrv: kmsrand.MockKMS{},
	}

	// CA cert
	subj := pkix.Name{
		CommonName:   "JTNET-Root-CA-1",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	caCSR, cakey, err := csr.New(subj, []string{}, rnd)
	if err != nil {
		panic(err.Error())
	}
	caCert, err := ca.New(caCSR, cakey, time.Hour*24*365*20, rnd)

	// Certificate generation and sign
	subj = pkix.Name{
		CommonName:   "host.test.gokrb5",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	r, key, _ := csr.New(subj, []string{"host.test.gokrb5"}, rnd)
	crt, err := csr.Sign(r, caCert, cakey, time.Hour*24*365*2, rnd)
	if err != nil {
		panic(err.Error())
	}

	// Write to files
	err = ioutil.WriteFile("/Users/turnerj/ca.crt", cert.PEMEncode(caCert), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/ca.key", cert.PEMEncodeRSAPrivateKey(cakey), 0600)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/www.crt", cert.PEMEncode(crt), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/www.key", cert.PEMEncodeRSAPrivateKey(key), 0600)
	if err != nil {
		panic(err.Error())
	}

	pair, _ := rsa.GenerateKey(rand.Reader, 2048)

	pubbytes := x509.MarshalPKCS1PublicKey(pair.Public().(*rsa.PublicKey))
	pvtbytes := x509.MarshalPKCS1PrivateKey(pair)

	fmt.Printf("pub %s\n", hex.EncodeToString(pubbytes))
	fmt.Printf("pvt %s\n", hex.EncodeToString(pvtbytes))

}
