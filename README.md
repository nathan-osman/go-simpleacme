## go-simpleacme

[![GoDoc](https://godoc.org/github.com/nathan-osman/go-simpleacme?status.svg)](https://godoc.org/github.com/nathan-osman/go-simpleacme)
[![MIT License](http://img.shields.io/badge/license-MIT-9370d8.svg?style=flat)](http://opensource.org/licenses/MIT)

The [golang.org/x/crypto/acme](https://godoc.org/golang.org/x/crypto/acme) package enables Go applications to obtain TLS certificates. However, the package is quite complex and using it in an application requires lots of boilerplate code. This package provides a much simpler interface, while still utilizing golang.org/x/crypto/acme behind the scenes.

### Usage

The following example demonstrates basic usage of go-simpleacme:

    import (
        "context"

        "github.com/nathan-osman/go-simpleacme"
    )

    ctx := context.TODO()

    // Create the client
    c := simpleacme.New()

    // Initialize the client with a private key - if the file
    // does not exist, a new key is generated
    if err := c.Initialize(ctx, "account.key"); err != nil {
        // handle error
    }

    // Obtain a certificate for the list of domain names - the
    // address is used for responding to challenges
    domains := []string{"example.com", "example.org"}
    if err := c.Create(ctx, "test.key", "test.crt", ":http", domains...); err != nil {
        // handle error
    }

That's it! If everything went well, you will now have three new files in the current directory:

- `account.key` the account key, which can be reused
- `test.key` the private key for the certificate
- `test.crt` the certificate bundle for the domain names
