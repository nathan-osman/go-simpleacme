package simpleacme

import (
	"context"
	"os"

	"golang.org/x/crypto/acme"
)

type Client struct {
	accountKey string
	client     *acme.Client
}

// New creates and initializes a new ACME client. The provided key is used for
// the account if it exists and a new key is generated if it does not.
func New(filename string) *Client {
	return &Client{
		accountKey: filename,
		client:     &acme.Client{},
	}
}

// Initialize performs account registration (if necessary).
func (c *Client) Initialize(ctx context.Context) error {
	newKey := false
	k, err := loadKey(c.accountKey)
	if err != nil && os.IsNotExist(err) {
		newKey = true
		k, err = generateKey(c.accountKey)
	}
	if err != nil {
		return err
	}
	if newKey {
		_, err := c.client.Register(ctx, nil, acme.AcceptTOS)
		if err != nil {
			return err
		}
	}
	c.client.Key = k
	return nil
}

// Authorize attempts to authorize the provided domain name in preparation for
// obtaining a TLS certificate. If a challenge is required, a temporary server
// will be set up at the provided address to respond to the challenge.
func (c *Client) Authorize(ctx context.Context, domain string, addr string) error {
	auth, err := c.client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	if auth.Status == acme.StatusValid {
		return nil
	}
	chal, err := findChallenge(auth)
	if err != nil {
		return err
	}
	return c.performChallenge(ctx, chal, addr)
}

// Create attempts to create a TLS certificate and private key for the
// specified domain names.
func (c *Client) Create(ctx context.Context, key, cert string, domains ...string) error {
	//...
	return nil
}
