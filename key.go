package simpleacme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

const keyType = "RSA PRIVATE KEY"

var ErrInvalidKey = errors.New("invalid key")

// loadKey attempts to load a private key from the specified file.
func loadKey(filename string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != keyType {
		return nil, ErrInvalidKey
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// generateKey creates a new 2048-bit RSA key and writes it to the specified
// file.
func generateKey(filename string) (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
	if err := ioutil.WriteFile(filename, b, 0600); err != nil {
		return nil, err
	}
	return k, nil
}
