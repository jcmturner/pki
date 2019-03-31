package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jcmturner/pki/certchain"
)

func main() {
	fqdn := flag.String("fqdn", "", "FQDN of endpoint to get certificate chain from")
	port := flag.Int("port", 443, "TCP port to connect to")
	out := flag.String("out", "./certchain.pem", "File to output certificate chain to")
	flag.Parse()

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
		os.Exit(1)
	}
	n, err := certchain.Write(fmt.Sprintf("%s:%d", *fqdn, *port), f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing cert chain: %v\n", err)
		os.Exit(1)
	}
	if n < 1 {
		fmt.Fprintln(os.Stderr, "no bytes written to output file")
		os.Exit(1)
	}
}
