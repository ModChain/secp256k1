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
  - Point addition and doubling
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

The package also provides an implementation of the Go standard library
`crypto/elliptic` `Curve` interface via the `S256` function so that it may be
used with other standard library packages such as `crypto/tls`, `crypto/x509`,
and `crypto/ecdsa`.

## Sub Packages

### schnorr

```go
import "github.com/KarpelesLab/secp256k1/schnorr"
```

Package `schnorr` provides Schnorr signing and verification optimized for the
secp256k1 curve.

Schnorr signatures offer several advantages over ECDSA:

- **Linearity** — easier to aggregate for multi-party, threshold, adaptor, and
  blind signature protocols
- **Stronger security proofs** — provably secure under SUF-CMA in the Random
  Oracle Model, meaning the only way to forge a signature is to solve the
  Elliptic Curve Discrete Logarithm Problem (ECDLP)
- **Batch verification** — supports faster batch verification unlike standard
  ECDSA
- **Compact** — 64-byte signatures (32-byte R.x + 32-byte s)

Key design features of the scheme:

- Signatures of the form `(R, s)` with only the `x` coordinate of `R` encoded
- Even `y` coordinate enforced for `R` to disambiguate without an extra byte
- Uses BLAKE-256 with 14 rounds for the challenge hash
- Deterministic nonces via RFC6979

#### Signing Algorithm

```
G = curve generator, n = curve order, d = private key, m = message (32 bytes)

1. Generate deterministic nonce k via RFC6979
2. R = k*G
3. Negate k if R.y is odd
4. r = R.x
5. e = BLAKE-256(r || m)
6. s = k - e*d mod n
7. Return (r, s)
```

#### Verification Algorithm

```
G = curve generator, n = curve order, p = field size, Q = public key

1. Fail if r >= p or s >= n
2. e = BLAKE-256(r || m)
3. R = s*G + e*Q
4. Fail if R is the point at infinity or R.y is odd
5. Verified if R.x == r
```

### ecckd

```go
import "github.com/KarpelesLab/secp256k1/ecckd"
```

Package `ecckd` implements BIP32 hierarchical deterministic key derivation for
secp256k1 extended keys. It supports:

- Master key generation from seed (`FromBitcoinSeed`, `FromSeed`)
- Hardened and non-hardened child key derivation
- Public and private extended key management
- Base58-encoded serialization and parsing (xpub/xprv format)
- Derivation along arbitrary paths (`Derive`, `DeriveWithIL`)
- Conversion to standard `crypto/ecdsa` and `secp256k1.PublicKey` types

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
