package simpleacme

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	"golang.org/x/crypto/acme"
)

var (
	ErrNoChallenges = errors.New("no suitable challenge found")
)

// findChallenge attempts to find a suitable challenge. Currently, only the
// http-01 challenge is supported.
func findChallenge(auth *acme.Authorization) (*acme.Challenge, error) {
	var chal *acme.Challenge
	for _, c := range auth.Challenges {
		if c.Type == "http-01" {
			chal = c
		}
	}
	if chal == nil {
		return nil, ErrNoChallenges
	}
	return chal, nil
}

// performChallenge creates a temporary server that ACME can access to verify
// ownership of a domain name.
func (c *Client) performChallenge(ctx context.Context, chal *acme.Challenge, addr string) error {
	response, err := c.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	var (
		b   = []byte(response)
		mux = http.NewServeMux()
	)
	mux.HandleFunc(
		c.client.HTTP01ChallengePath(chal.Token),
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
			w.Write(b)
		},
	)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil
	}
	defer l.Close()
	go func() {
		http.Serve(l, mux)
	}()
	chal, err = c.client.Accept(ctx, chal)
	if err != nil {
		return err
	}
	_, err = c.client.WaitAuthorization(ctx, chal.URI)
	return err
}
