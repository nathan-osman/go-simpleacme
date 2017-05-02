## go-simpleacme

[![GoDoc](https://godoc.org/github.com/nathan-osman/go-simpleacme?status.svg)](https://godoc.org/github.com/nathan-osman/go-simpleacme)
[![MIT License](http://img.shields.io/badge/license-MIT-9370d8.svg?style=flat)](http://opensource.org/licenses/MIT)

The [golang.org/x/crypto/acme](https://godoc.org/golang.org/x/crypto/acme) package enables Go applications to obtain TLS certificates. However, the package is quite complex and using it in an application requires lots of boilerplate code. This package provides a much simpler interface, while still utilizing golang.org/x/crypto/acme behind the scenes.

### Basic Usage

The following example demonstrates basic usage of go-simpleacme:

    import (
        "context"

        "github.com/nathan-osman/go-simpleacme"
    )

    ctx := context.TODO()

    // Create the client - the key will be generated if it does not exist
    c, err := simpleacme.New(ctx, "account.key")
    if err != nil {
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

### Advanced Usage

go-simpleacme also provides a certificate manager:

    import (
        "context"

        "github.com/nathan-osman/go-simpleacme/manager"
    )

    ctx := context.TODO()

    // Create a certificate manager that will store all keys
    // and certificates in /etc/certs
    m, err := simpleacme.New(ctx, ":http", "/etc/certs", nil)
    if err != nil {
        // handle error
    }
    defer m.Close()

    // Add a couple of domain names to the manager
    m.Add(ctx, "example.com", "example.org")

The manager will automatically obtain TLS certificates for the two domain names (combining them into a single certificate to reduce ACME requests). When the certificates are about to expire, they will be automatically renewed.
