// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package secp256k1 implements optimized secp256k1 elliptic curve operations in
pure Go.

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
  - FieldVal type for working modulo the secp256k1 field prime
  - ModNScalar type for working modulo the secp256k1 group order
  - Elliptic curve operations in Jacobian projective coordinates
  - Point addition
  - Point doubling
  - Scalar multiplication with an arbitrary point
  - Scalar multiplication with the base point (group generator)
  - Point decompression from a given x coordinate
  - Nonce generation via RFC6979 with support for extra data and version
    information that can be used to prevent nonce reuse between signing
    algorithms

It also provides an implementation of the Go standard library crypto/elliptic
Curve interface via the S256 function so that it may be used with other packages
in the standard library such as crypto/tls, crypto/x509, and crypto/ecdsa.
However, in the case of ECDSA, it is highly recommended to use the ecdsa sub
package of this package instead since it is optimized specifically for secp256k1
and is significantly faster as a result.

This package also provides data structures and functions necessary to produce and
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
Finally, a comprehensive suite of tests is provided to provide a high level of
quality assurance.
*/
package secp256k1
