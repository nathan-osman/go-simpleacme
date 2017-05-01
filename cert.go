package simpleacme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

const certType = "CERTIFICATE"

var ErrNoDomains = errors.New("no domain names provided")

// createCSR creates a certificate signing requests for the provided domains.
func createCSR(k *rsa.PrivateKey, domains ...string) ([]byte, error) {
	if len(domains) == 0 {
		return nil, ErrNoDomains
	}
	return x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: domains[0]},
			DNSNames: domains[1:],
		},
		k,
	)
}

// createCert obtains a certificate for the provided CSR.
func (c *Client) createCert(ctx context.Context, csr []byte, cert string) error {
	ders, _, err := c.client.CreateCert(ctx, csr, 90*24*time.Hour, true)
	if err != nil {
		return err
	}
	w, err := os.Create(cert)
	if err != nil {
		return err
	}
	defer w.Close()
	for _, b := range ders {
		err := pem.Encode(w, &pem.Block{
			Type:  certType,
			Bytes: b,
		})
		if err != nil {
			return err
		}
	}
	return nil
}
