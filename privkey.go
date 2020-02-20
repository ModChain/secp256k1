// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
)

// PrivateKey provides facilities for working with secp256k1 private keys within
// this package and includes functionality such as serializing and parsing them
// as well as computing their associated public key.
type PrivateKey struct {
	key ModNScalar
}

// NewPrivateKey instantiates a new private key from a scalar encoded as a
// big integer.
func NewPrivateKey(key *ModNScalar) *PrivateKey {
	return &PrivateKey{key: *key}
}

// PrivKeyFromBytes returns a private based on the provided byte slice which is
// interpreted as an unsigned 256-bit big-endian integer in the range [0, N-1],
// where N is the order of the curve.
//
// Note that this means passing a slice with more than 32 bytes is truncated and
// that truncated value is reduced modulo N.  It is up to the caller to either
// provide a value in the appropriate range or choose to accept the described
// behavior.
//
// Typically callers should simply make use of GeneratePrivateKey when creating
// private keys which properly handles generation of appropriate values.
func PrivKeyFromBytes(privKeyBytes []byte) *PrivateKey {
	var d ModNScalar
	d.SetByteSlice(privKeyBytes)
	return NewPrivateKey(&d)
}

// GeneratePrivateKey returns a private key that is suitable for use with
// secp256k1.
func GeneratePrivateKey() (*PrivateKey, error) {
	key, err := ecdsa.GenerateKey(S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return PrivKeyFromBytes(key.D.Bytes()), nil
}

// PubKey computes and returns the public key corresponding to this private key.
// PubKey returns the PublicKey corresponding to this private key.
func (p *PrivateKey) PubKey() *PublicKey {
	var result jacobianPoint
	scalarBaseMultJacobian(&p.key, &result)
	return NewPublicKey(jacobianToBigAffine(&result))
}

// Sign generates an ECDSA signature for the provided hash (which should be the
// result of hashing a larger message) using the private key. Produced signature
// is deterministic (same message and same key yield the same signature) and
// canonical in accordance with RFC6979 and BIP0062.
func (p *PrivateKey) Sign(hash []byte) *Signature {
	signature, _ := signRFC6979(p, hash)
	return signature
}

// PrivKeyBytesLen defines the length in bytes of a serialized private key.
const PrivKeyBytesLen = 32

// Serialize returns the private key as a 256-bit big-endian binary-encoded
// number, padded to a length of 32 bytes.
func (p PrivateKey) Serialize() []byte {
	privKeyBytes := p.key.Bytes()
	return privKeyBytes[:]
}
