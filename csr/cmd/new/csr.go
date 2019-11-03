package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"flag"
	"log"
	"path/filepath"
	"strings"

	"github.com/jcmturner/pki/certificate"
	"github.com/jcmturner/pki/csr"
)

func main() {
	cn := flag.String("cn", "", "Common Name for the certificate authority")
	c := flag.String("c", "", "2 character ISO format country code (eg GB, US)")
	o := flag.String("o", "", "Organisation name")
	ou := flag.String("ou", "", "Organisational unit")
	l := flag.String("l", "", "Locality or city")
	s := flag.String("s", "", "State, county, region or province")
	sns := flag.String("sans", "", "Comma separated list of Subject Alternative Names")
	out := flag.String("out", "./", "Output path for certificate and private key")
	flag.Parse()

	sans := strings.Split(*sns, ",")

	subj := pkix.Name{CommonName: *cn}
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

	cr, key, err := csr.New(subj, sans, rand.Reader)
	if err != nil {
		log.Fatalf("error creating CA request: %v\n", err)
	}

	err = certificate.WriteKeyFile(key, filepath.Clean(*out)+"/"+*cn+".key")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("private key writen to %s", filepath.Clean(*out)+"/"+*cn+".key")

	err = csr.WriteFile(cr, filepath.Clean(*out)+"/"+*cn+".csr")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("CSR writen to %s", filepath.Clean(*out)+"/"+*cn+".csr")
}
