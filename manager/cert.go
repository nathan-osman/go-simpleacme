package manager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"time"
)

const (
	day  = 24 * time.Hour
	week = 7 * day

	certType = "CERTIFICATE"
)

var errInvalidCert = errors.New("invalid certificate")

// Key determines the absolute filename for a private key.
func (m *Manager) Key(domain string) string {
	return path.Join(m.dir, fmt.Sprintf("%s.key", domain))
}

// Cert determines the absolute filename for a certificate.
func (m *Manager) Cert(domain string) string {
	return path.Join(m.dir, fmt.Sprintf("%s.crt", domain))
}

// readCert verifies that the specified certificate exist and retrieves the
// expiry time of the first certificate in the chain.
func readCert(cert string) (time.Time, error) {
	b, err := ioutil.ReadFile(cert)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != certType {
		return time.Time{}, errInvalidCert
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

// copyFile copies a file to a new destination.
func copyFile(src, dest string, perm os.FileMode) error {
	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer w.Close()
	_, err = io.Copy(w, r)
	return err
}

// load attempts to load certificates from disk for all of the current domains.
// A list of domains that were loaded and a list of those that require renewal
// is returned.
func (m *Manager) load() ([]string, []string) {
	var (
		loaded   = []string{}
		expiring = []string{}
		now      = time.Now()
	)
	for d, expires := range m.certs {
		if expires.IsZero() {
			if _, err := os.Stat(m.Key(d)); err != nil {
				m.log.Debugf("cannot open private key for %s", d)
				goto fail
			}
			e, err := readCert(m.Cert(d))
			if err != nil {
				m.log.Debugf("certificate for %s: %s", d, err)
				goto fail
			}
			expires = e
		}
		if now.Add(2 * week).After(expires) {
			m.log.Debugf("certificate for %s expires soon", d)
			goto fail
		}
		m.certs[d] = expires
		loaded = append(loaded, d)
		continue
	fail:
		expiring = append(expiring, d)
	}
	return loaded, expiring
}

// renew attempts to obtain TLS certificates for the provided domain names.
func (m *Manager) renew(ctx context.Context) error {
	loaded, expiring := m.load()
	defer func() {
		if len(loaded) != 0 {
			m.callback(loaded...)
		}
	}()
	if len(expiring) != 0 {
		var (
			key  = m.Key(expiring[0])
			cert = m.Cert(expiring[0])
		)
		if err := m.client.Create(ctx, key, cert, m.addr, expiring...); err != nil {
			return err
		}
		e, err := readCert(cert)
		if err != nil {
			return err
		}
		m.certs[expiring[0]] = e
		loaded = append(loaded, expiring[0])
		for _, d := range expiring[1:] {
			if err := copyFile(key, m.Key(d), 0600); err != nil {
				return err
			}
			if err := copyFile(cert, m.Cert(d), 0644); err != nil {
				return err
			}
			m.certs[d] = e
			loaded = append(loaded, d)
		}
	}
	return nil
}
