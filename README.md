secp256k1
=========

[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://godoc.org/github.com/ModChain/secp256k1?status.svg)](https://godoc.org/github.com/ModChain/secp256k1)

Package secp256k1 implements optimized secp256k1 elliptic curve operations.

This package provides an optimized pure Go implementation of elliptic curve
cryptography operations over the secp256k1 curve as well as data structures and
functions for working with public and private secp256k1 keys.  See
https://www.secg.org/sec2-v2.pdf for details on the standard.

In addition, sub packages are provided to produce, verify, parse, and serialize
ECDSA signatures and EC-Schnorr-DCRv0 (a custom Schnorr-based signature scheme
specific to Decred) signatures.  See the README.md files in the relevant sub
packages for more details about those aspects.

An overview of the features provided by this package are as follows:

- Private key generation, serialization, and parsing
- Public key generation, serialization and parsing per ANSI X9.62-1998
  - Parses uncompressed, compressed, and hybrid public keys
  - Serializes uncompressed and compressed public keys
- Specialized types for performing optimized and constant time field operations
  - `FieldVal` type for working modulo the secp256k1 field prime
  - `ModNScalar` type for working modulo the secp256k1 group order
- Elliptic curve operations in Jacobian projective coordinates
  - Point addition
  - Point doubling
  - Scalar multiplication with an arbitrary point
  - Scalar multiplication with the base point (group generator)
- Point decompression from a given x coordinate
- Nonce generation via RFC6979 with support for extra data and version
  information that can be used to prevent nonce reuse between signing algorithms

It also provides an implementation of the Go standard library `crypto/elliptic`
`Curve` interface via the `S256` function so that it may be used with other
packages in the standard library such as `crypto/tls`, `crypto/x509`, and
`crypto/ecdsa`.  However, in the case of ECDSA, it is highly recommended to use
the `ecdsa` sub package of this package instead since it is optimized
specifically for secp256k1 and is significantly faster as a result.

Although this package was primarily written for dcrd, it has intentionally been
designed so it can be used as a standalone package for any projects needing to
use optimized secp256k1 elliptic curve cryptography.

Finally, a comprehensive suite of tests is provided to provide a high level of
quality assurance.

## Installation and Updating

This package is part of the `github.com/ModChain/secp256k1` module.
Use the standard go tooling for working with modules to incorporate it.

## Examples

* [Encryption](https://pkg.go.dev/github.com/ModChain/secp256k1#example-package-EncryptDecryptMessage)
  Demonstrates encrypting and decrypting a message using a shared key derived
  through ECDHE.

## License

Package secp256k1 is licensed under the [copyfree](http://copyfree.org) ISC
License.

ecdsa
=====

Package ecdsa provides secp256k1-optimized ECDSA signing and verification.

This package provides data structures and functions necessary to produce and
verify deterministic canonical signatures in accordance with RFC6979 and
BIP0062, optimized specifically for the secp256k1 curve using the Elliptic Curve
Digital Signature Algorithm (ECDSA), as defined in FIPS 186-3.  See
https://www.secg.org/sec2-v2.pdf for details on the secp256k1 standard.

It also provides functions to parse and serialize the ECDSA signatures with the
more strict Distinguished Encoding Rules (DER) of ISO/IEC 8825-1 and some
additional restrictions specific to secp256k1.

In addition, it supports a custom "compact" signature format which allows
efficient recovery of the public key from a given valid signature and message
hash combination.

A comprehensive suite of tests is provided to ensure proper functionality.

## ECDSA use in Decred

At the time of this writing, ECDSA signatures are heavily used for proving coin
ownership in Decred as the vast majority of transactions consist of what is
effectively transferring ownership of coins to a public key associated with a
private key only known to the recipient of the coins along with an encumbrance
that requires an ECDSA signature that proves the new owner possesses the private
key without actually revealing it.

## Installation and Updating

This package is part of the `github.com/decred/dcrd/dcrec/secp256k1/v4` module.
Use the standard go tooling for working with modules to incorporate it.

## Examples

* [Sign Message](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa#example-package-SignMessage)  
  Demonstrates signing a message with a secp256k1 private key that is first
  parsed from raw bytes and serializing the generated signature.

* [Verify Signature](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa#example-Signature.Verify)  
  Demonstrates verifying a secp256k1 signature against a public key that is
  first parsed from raw bytes.  The signature is also parsed from raw bytes.

## License

Package ecdsa is licensed under the [copyfree](http://copyfree.org) ISC License.
