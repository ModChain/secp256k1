secp256k1
=========

[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://pkg.go.dev/badge/github.com/KarpelesLab/secp256k1.svg)](https://pkg.go.dev/github.com/KarpelesLab/secp256k1)
[![Tests](https://github.com/KarpelesLab/secp256k1/actions/workflows/test.yml/badge.svg)](https://github.com/KarpelesLab/secp256k1/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/secp256k1/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/secp256k1?branch=master)

Package secp256k1 implements optimized secp256k1 elliptic curve operations in
pure Go.

This package provides elliptic curve cryptography operations over the secp256k1
curve as well as data structures and functions for working with public and
private secp256k1 keys. See https://www.secg.org/sec2-v2.pdf for details on the
standard.

## Features

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
- ECDSA signature creation, verification, parsing, and serialization
  - Deterministic canonical signatures in accordance with RFC6979 and BIP0062
  - DER serialization per ISO/IEC 8825-1
  - Compact signature format with public key recovery
- ECDH shared secret generation (RFC 5903)

It also provides an implementation of the Go standard library `crypto/elliptic`
`Curve` interface via the `S256` function so that it may be used with other
packages in the standard library such as `crypto/tls`, `crypto/x509`, and
`crypto/ecdsa`.

## Sub Packages

### schnorr

Package `schnorr` provides Schnorr signing and verification using a custom
scheme named EC-Schnorr-DCRv0, optimized for the secp256k1 curve. Schnorr
signatures offer advantages over ECDSA including simpler aggregation, provable
security under weaker assumptions, and support for faster batch verification.

```go
import "github.com/KarpelesLab/secp256k1/schnorr"
```

### ecckd

Package `ecckd` implements BIP32 hierarchical deterministic key derivation for
secp256k1 extended keys. It supports:

- Master key generation from seed (`FromBitcoinSeed`, `FromSeed`)
- Hardened and non-hardened child key derivation
- Public and private extended key management
- Base58-encoded serialization and parsing (xpub/xprv format)
- Conversion to standard `crypto/ecdsa` key types

```go
import "github.com/KarpelesLab/secp256k1/ecckd"
```

## Examples

* [Encryption](https://pkg.go.dev/github.com/KarpelesLab/secp256k1#example-package-EncryptDecryptMessage)
  Demonstrates encrypting and decrypting a message using a shared key derived
  through ECDHE.

* [Sign Message](https://pkg.go.dev/github.com/KarpelesLab/secp256k1#example-package-SignMessage)
  Demonstrates signing a message with a secp256k1 private key that is first
  parsed from raw bytes and serializing the generated signature.

* [Verify Signature](https://pkg.go.dev/github.com/KarpelesLab/secp256k1#example-Signature.Verify)
  Demonstrates verifying a secp256k1 signature against a public key that is
  first parsed from raw bytes. The signature is also parsed from raw bytes.

## License

Package secp256k1 is licensed under the [copyfree](http://copyfree.org) ISC
License.
