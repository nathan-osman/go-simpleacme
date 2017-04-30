## go-simpleacme

The [golang.org/x/crypto/acme](https://godoc.org/golang.org/x/crypto/acme) package enables Go applications to obtain TLS certificates. However, the package is quite complex and using it in an application requires lots of boilerplate code. This package provides a much simpler interface, while still utilizing golang.org/x/crypto/acme behind the scenes.

### Usage

The following example demonstrates basic usage of go-simpleacme:

    import (
        "context"

        "github.com/nathan-osman/go-simpleacme"
    )

    ctx := context.TODO()

    // Parameter is a path to the account key
    // it will be created if it does not already exist
    c, err := simpleacme.New("account.key")
    if err != nil {
        // handle error
    }

    // Authorize the domain name "example.com"
    if err := c.Authorize(ctx, "example.com"); err != nil {
        // handle error
    }

    // Obtain a certificate for a list of domain names
    // a single certificate with multiple SANs will be issued
    domains := []string{"example.com", "example.org"}
    if err := c.Create(ctx, "test.key", "test.crt", domains...); err != nil {
        // handle error
    }

That's it! If everything went well, you will now have three new files in the current directory:

- `account.key` the account key, which can be reused
- `test.key` the private key for the certificate
- `test.crt` the certificate bundle for the domain names
