package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"io/ioutil"
	"time"

	"github.com/jcmturner/pki/ca"
	"github.com/jcmturner/pki/certificate"
	"github.com/jcmturner/pki/csr"
)

func main() {
	// KMS Random number reader

	// CA certificate
	subj := pkix.Name{
		CommonName:   "JTNET-Root-CA-1",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	caCSR, cakey, err := csr.New(subj, []string{}, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	caCert, err := ca.New(caCSR, cakey, time.Hour*24*365*20, rand.Reader)

	// Certificate generation and sign
	subj = pkix.Name{
		CommonName:   "www.jtnet.co.uk",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	r, key, _ := csr.New(subj, []string{"www.jtnet.co.uk", "www.jtlan.co.uk"}, rand.Reader)
	crt, err := ca.Sign(r, caCert, cakey, time.Hour*24*365*2, rand.Reader)
	if err != nil {
		panic(err.Error())
	}

	// Certificate generation and sign
	subj = pkix.Name{
		CommonName:   "jtmac.jtlan.co.uk",
		Country:      []string{"GB"},
		Organization: []string{"JTNET"},
	}
	r, mackey, _ := csr.New(subj, []string{"jtmac.jtlan.co.uk"}, rand.Reader)
	maccrt, err := ca.Sign(r, caCert, cakey, time.Hour*24*365*2, rand.Reader)
	if err != nil {
		panic(err.Error())
	}

	// Write to files
	err = ioutil.WriteFile("/Users/turnerj/jtca.crt", certificate.PEMEncode(caCert), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/jtca.key", certificate.PEMEncodeRSAPrivateKey(cakey), 0600)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/jtwww.crt", certificate.PEMEncode(crt), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/jtwww.key", certificate.PEMEncodeRSAPrivateKey(key), 0600)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/jtmac.crt", certificate.PEMEncode(maccrt), 0644)
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile("/Users/turnerj/jtmac.key", certificate.PEMEncodeRSAPrivateKey(mackey), 0600)
	if err != nil {
		panic(err.Error())
	}
}
