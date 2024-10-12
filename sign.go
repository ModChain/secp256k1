package secp256k1

import (
	"crypto"
	"io"
)

type SignatureFormat uint

const (
	SignFormatDER SignatureFormat = iota // DER format by default
	SignFormatCompact
)

type SignOptions struct {
	Format SignatureFormat
	Hash   crypto.Hash
}

func (s *SignOptions) HashFunc() crypto.Hash {
	return s.Hash
}

// Sign will sign the provided digest, returning the resulting signature. [SignOptions] can be used
// to pass options.
func (privkey *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var opt *SignOptions
	if o, ok := opts.(*SignOptions); ok {
		opt = o
	} else {
		opt = &SignOptions{}
	}

	sig, pubKeyRecoveryCode := signRFC6979(privkey, digest)

	switch opt.Format {
	case SignFormatCompact:
		var b [65]byte
		b[0] = pubKeyRecoveryCode
		sig.r.PutBytesUnchecked(b[1:33])
		sig.s.PutBytesUnchecked(b[33:65])
		return b[:], nil
	case SignFormatDER:
		fallthrough
	default:
		return sig.Serialize(), nil // DER
	}
}
