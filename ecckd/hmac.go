package ecckd

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/ModChain/secp256k1"
)

var (
	ErrShaKeyInvalid = errors.New("generated key zero or overflow, try next one")
)

// hmacCKD returns key and chainCode for a given seed and salt.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func hmacCKD(seed, salt []byte) (key, chainCode []byte, err error) {
	data := hmac.New(sha512.New, salt)
	if _, err = data.Write(seed); err != nil {
		return
	}
	I := data.Sum(nil)

	key = I[:32]       // IL
	chainCode = I[32:] // IR

	// In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2127.)
	keyI := new(big.Int).SetBytes(key)
	if keyI.Cmp(secp256k1.S256().N) >= 0 || keyI.Sign() == 0 {
		err = ErrShaKeyInvalid
	}

	return
}
