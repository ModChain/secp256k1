package ecckd

import (
	"crypto/sha256"
	"math/big"

	"github.com/ModChain/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

func doubleSha256(in []byte) []byte {
	a := sha256.Sum256(in)
	a = sha256.Sum256(a[:])
	return a[:]
}

// ripemd160 + sha256
func rmd160sha256(in []byte) []byte {
	a := sha256.Sum256(in)
	rmd := ripemd160.New()
	rmd.Write(a[:])
	return rmd.Sum(nil)
}

func asFV(v *big.Int) *secp256k1.FieldVal {
	fv := new(secp256k1.FieldVal)
	fv.SetByteSlice(v.Bytes())
	return fv
}

func paddedAppend(size int, dst, src []byte) []byte {
	if len(src) < size {
		appd := size - len(src) // number of bytes to append
		dstl := len(dst)
		if cap(dst)-dstl >= appd {
			// easy
			dst = dst[:len(dst)+appd]
			for i := dstl; i < len(dst); i++ {
				dst[i] = 0
			}
		} else {
			// need to grow (=reallocate) dst, prepare for receive src as well
			ndst := make([]byte, dstl+appd, dstl+appd+len(src))
			copy(ndst, dst)
		}
	}
	return append(dst, src...)
}
