// Copyright (c) 2020-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package schnorr provides Schnorr signing and verification via secp256k1.

This package provides data structures and functions necessary to produce and
verify deterministic canonical Schnorr signatures.  The signatures and
implementation are optimized specifically for the secp256k1 curve.  See
https://www.secg.org/sec2-v2.pdf for details on the secp256k1 standard.

It also provides functions to parse and serialize the Schnorr signatures
according to the specification described in the project README.

# Overview

A Schnorr signature is a digital signature scheme that is known for its
simplicity, provable security and efficient generation of short signatures.

It provides many advantages over ECDSA signatures that make them ideal for use
with the only real downside being that they are not well standardized at the
time of this writing.

Some of the advantages over ECDSA include:

  - They are linear which makes them easier to aggregate and use in protocols
    that build on them such as multi-party signatures, threshold signatures,
    adaptor signatures, and blind signatures
  - They are provably secure with weaker assumptions than the best known
    security proofs for ECDSA.  Specifically they are provably secure under
    SUF-CMA in the ROM which guarantees that as long as the hash function
    behaves ideally, the only way to break Schnorr signatures is by solving
    the ECDLP.
  - Their relatively straightforward and efficient aggregation properties make
    them excellent for scalability and allow them to provide some nice privacy
    characteristics
  - They support faster batch verification unlike the standardized version of
    ECDSA signatures

# Signature Scheme

The scheme has the following key design features:

  - Uses signatures of the form (R, s)
  - Produces 64-byte signatures by only encoding the x coordinate of R
  - Enforces even y coordinates for R to support efficient verification by
    disambiguating the two possible y coordinates
  - Canonically encodes both components of the signature with 32-bytes each
  - Uses BLAKE-256 with 14 rounds for the hash function to calculate challenge e
  - Uses RFC6979 to obviate the need for an entropy source at signing time
  - Produces deterministic signatures for a given message and private key pair

See the project README for the full signing and verification algorithms.
*/
package schnorr
