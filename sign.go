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
// to pass options. By default DER format will be used for signatures, however compact format can be
// specified via opts.
func (privkey *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var opt *SignOptions
	if o, ok := opts.(*SignOptions); ok {
		opt = o
	} else {
		opt = &SignOptions{}
	}

	sig := signRFC6979(privkey, digest)

	switch opt.Format {
	case SignFormatCompact:
		return sig.ExportCompact(true, 0), nil
	case SignFormatDER:
		fallthrough
	default:
		return sig.Serialize(), nil // DER
	}
}
