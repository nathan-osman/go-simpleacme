package simpleacme

import (
	"context"
	"os"

	"golang.org/x/crypto/acme"
)

type Client struct {
	client *acme.Client
}

// New creates a new ACME client. If the key does not exist, a new one is
// generated and registered.
func New(ctx context.Context, key string) (*Client, error) {
	client := &acme.Client{}
	k, err := loadKey(key)
	if err != nil {
		if os.IsNotExist(err) {
			k, err = generateKey(key)
			if err != nil {
				return nil, err
			}
			client.Key = k
			if _, err := client.Register(ctx, nil, acme.AcceptTOS); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		client.Key = k
	}
	return &Client{
		client: client,
	}, nil
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
