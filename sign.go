package secp256k1

import (
	"crypto"
	"io"
)

type SignOptions struct {
	Hash crypto.Hash
}

func (s *SignOptions) HashFunc() crypto.Hash {
	return s.Hash
}

// Sign will sign the provided digest, returning the resulting signature. [SignOptions] can be used
// to pass options.
func (privkey *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sign := Sign(privkey, digest)
	return sign.Serialize(), nil // DER
}
