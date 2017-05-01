package simpleacme

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"time"
)

const certType = "CERTIFICATE"

// createCSR creates a certificate signing requests for the provided domains.
func createCSR(k *rsa.PrivateKey, domains ...string) ([]byte, error) {
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
	buf := &bytes.Buffer{}
	for _, b := range ders {
		err := pem.Encode(buf, &pem.Block{
			Type:  certType,
			Bytes: b,
		})
		if err != nil {
			return err
		}
	}
	return ioutil.WriteFile(cert, buf.Bytes(), 0644)
}