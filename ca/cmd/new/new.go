package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"flag"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/jcmturner/pki/ca"
	"github.com/jcmturner/pki/certificate"
	csr "github.com/jcmturner/pki/csr"
)

func main() {
	cn := flag.String("cn", "", "Common Name for the certificate authority")
	c := flag.String("c", "", "2 character ISO format country code (eg GB, US)")
	o := flag.String("o", "", "Organisation name")
	ou := flag.String("ou", "", "Organisational unit")
	l := flag.String("l", "", "Locality or city")
	s := flag.String("s", "", "State, county, region or province")
	out := flag.String("out", "./", "Output path for certificate and private key")
	d := flag.Duration("duration", time.Hour*24*365*20, "Expiration duration of the CA")
	flag.Parse()

	subj := pkix.Name{
		CommonName: *cn,
	}
	if *c != "" {
		subj.Country = strings.Split(*c, ",")
	}
	if *o != "" {
		subj.Organization = strings.Split(*o, ",")
	}
	if *ou != "" {
		subj.OrganizationalUnit = strings.Split(*ou, ",")
	}
	if *l != "" {
		subj.Locality = strings.Split(*l, ",")
	}
	if *s != "" {
		subj.Province = strings.Split(*s, ",")
	}
	var san []string

	car, key, err := csr.New(subj, san, rand.Reader)
	if err != nil {
		log.Fatalf("error creating CA request: %v\n", err)
	}

	cert, err := ca.New(car, key, *d, rand.Reader)
	if err != nil {
		log.Fatalf("error creating CA certificate: %v\n", err)
	}

	err = certificate.WriteCertFile(cert, filepath.Clean(*out)+"/CAcert.pem")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("CA certificate writen to %s", filepath.Clean(*out)+"/CAcert.pem")

	err = certificate.WriteKeyFile(key, filepath.Clean(*out)+"/CAkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("CA private key writen to %s", filepath.Clean(*out)+"/CAkey.pem")
}
