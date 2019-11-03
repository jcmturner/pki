package certchain

import (
	"crypto/tls"
	"crypto/x509"
	"io"

	"github.com/jcmturner/pki/certificate"
)

// conn establishes a connection without verifying the certificate
func conn(addr string) (*tls.Conn, error) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	return tls.Dial("tcp", addr, cfg)
}

// Bytes returns a byte slice of the complete certificate chain.
// The address must be in the form <fqdn>:<port>
func Bytes(addr string) ([]byte, error) {
	var b []byte
	conn, err := conn(addr)
	if err != nil {
		return b, err
	}
	certs := conn.ConnectionState().PeerCertificates
	for _, c := range certs {
		b = append(b, certificate.PEMEncode(c)...)
	}
	return b, nil
}

// Write returns writes the certificate chain to the io.Writer provided.
// The values returned are the number of bytes written and any error.
// The address must be in the form <fqdn>:<port>
func Write(addr string, w io.Writer) (int, error) {
	b, err := Bytes(addr)
	if err != nil {
		return 0, err
	}
	return w.Write(b)
}

// CertPool returns the certificate chain as a x509.CertPool.
// The address must be in the form <fqdn>:<port>
func CertPool(addr string) (*x509.CertPool, error) {
	cp := x509.NewCertPool()
	conn, err := conn(addr)
	if err != nil {
		return cp, err
	}
	certs := conn.ConnectionState().PeerCertificates
	for _, c := range certs {
		cp.AddCert(c)
	}
	return cp, nil
}
