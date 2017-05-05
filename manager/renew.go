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

// findExpiring determines which domains are expiring.
func (m *Manager) findExpiring() []string {
	var (
		domains = []string{}
		now     = time.Now()
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
			m.certs[d] = e
		}
		if now.Add(2 * week).After(expires) {
			m.log.Debugf("certificate for %s expires soon", d)
			goto fail
		}
		continue
	fail:
		domains = append(domains, d)
	}
	return domains
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

// renew iterates over all of the domains and attempts to renew all that are
// about to expire.
func (m *Manager) renew(ctx context.Context) error {
	domains := m.findExpiring()
	m.log.Debugf("%d domain(s) require renewal", len(domains))
	if len(domains) != 0 {
		var (
			key  = m.Key(domains[0])
			cert = m.Cert(domains[0])
		)
		if err := m.client.Create(ctx, key, cert, m.addr, domains...); err != nil {
			return err
		}
		e, err := readCert(cert)
		if err != nil {
			return err
		}
		m.certs[domains[0]] = e
		for _, d := range domains[1:] {
			if err := copyFile(key, m.Key(d), 0600); err != nil {
				return err
			}
			if err := copyFile(cert, m.Cert(d), 0644); err != nil {
				return err
			}
			m.certs[d] = e
		}
	}
	if m.callback != nil {
		if err := m.callback(); err != nil {
			return err
		}
	}
	return nil
}
