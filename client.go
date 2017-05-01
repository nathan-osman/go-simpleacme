package simpleacme

import (
	"context"
	"os"

	"golang.org/x/crypto/acme"
)

type Client struct {
	client *acme.Client
}

// New creates a new ACME client.
func New(filename string) *Client {
	return &Client{
		client: &acme.Client{},
	}
}

// Initialize performs account registration (if necessary).
func (c *Client) Initialize(ctx context.Context, key string) error {
	k, err := loadKey(key)
	if err != nil {
		if os.IsNotExist(err) {
			k, err := generateKey(key)
			if err != nil {
				return err
			}
			if _, err := c.client.Register(ctx, nil, acme.AcceptTOS); err != nil {
				return err
			}
			c.client.Key = k
			return nil
		} else {
			return err
		}
	}
	c.client.Key = k
	return nil
}

// Create attempts to create a TLS certificate and private key for the
// specified domain names. The provided address is used for challenges.
func (c *Client) Create(ctx context.Context, key, cert, addr string, domains ...string) error {
	for _, d := range domains {
		if err := c.authorize(ctx, d, addr); err != nil {
			return err
		}
	}
	k, err := generateKey(key)
	if err != nil {
		return err
	}
	b, err := createCSR(k, domains...)
	if err != nil {
		return err
	}
	return c.createCert(ctx, b, cert)
}
