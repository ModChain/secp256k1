// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package schnorr

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

// Signature is a type representing a Schnorr signature.
type Signature struct {
	r *big.Int
	s *big.Int
}

const (
	// SignatureSize is the size of an encoded Schnorr signature.
	SignatureSize = 64

	// scalarSize is the size of an encoded big endian scalar.
	scalarSize = 32
)

var (
	// bigZero is the big representation of zero.
	bigZero = new(big.Int).SetInt64(0)

	// rfc6979ExtraDataV0 is the extra data to feed to RFC6979 when generating
	// the deterministic nonce for the EC-Schnorr-DCRv0 scheme.  This ensures
	// the same nonce is not generated for the same message and key as for other
	// signing algorithms such as ECDSA.
	//
	// It is equal to BLAKE-256([]byte("EC-Schnorr-DCRv0")).
	rfc6979ExtraDataV0 = [32]byte{
		0x0b, 0x75, 0xf9, 0x7b, 0x60, 0xe8, 0xa5, 0x76,
		0x28, 0x76, 0xc0, 0x04, 0x82, 0x9e, 0xe9, 0xb9,
		0x26, 0xfa, 0x6f, 0x0d, 0x2e, 0xea, 0xec, 0x3a,
		0x4f, 0xd1, 0x44, 0x6a, 0x76, 0x83, 0x31, 0xcb,
	}
)

// NewSignature instantiates a new signature given some R,S values.
func NewSignature(r, s *big.Int) *Signature {
	return &Signature{r, s}
}

// Serialize returns the Schnorr signature in the more strict format.
//
// The signatures are encoded as
//   sig[0:32]  R, a point encoded as big endian
//   sig[32:64] S, scalar multiplication/addition results = (ab+c) mod l
//     encoded also as big endian
func (sig Signature) Serialize() []byte {
	rBytes := bigIntToEncodedBytes(sig.r)
	sBytes := bigIntToEncodedBytes(sig.s)

	all := append(rBytes[:], sBytes[:]...)

	return all
}

// ParseSignature parses a signature according to the EC-Schnorr-DCRv0
// specification and enforces the following additional restrictions specific to
// secp256k1:
//
// - The r component must be in the valid range for secp256k1 field elements
// - The s component must be in the valid range for secp256k1 scalars
func ParseSignature(sig []byte) (*Signature, error) {
	// The signature must be the correct length.
	sigLen := len(sig)
	if sigLen < SignatureSize {
		str := fmt.Sprintf("malformed signature: too short: %d < %d", sigLen,
			SignatureSize)
		return nil, signatureError(ErrSigTooShort, str)
	}
	if sigLen > SignatureSize {
		str := fmt.Sprintf("malformed signature: too long: %d > %d", sigLen,
			SignatureSize)
		return nil, signatureError(ErrSigTooLong, str)
	}

	// The signature is validly encoded at this point, however, enforce
	// additional restrictions to ensure r is in the range [0, p-1], and s is in
	// the range [0, n-1] since valid Schnorr signatures are required to be in
	// that range per spec.
	//
	// Notice that rejecting these values here is not strictly required because
	// they are also checked when verifying the signature, but there really
	// isn't a good reason not to fail early here on signatures that do not
	// conform to the spec.
	var r secp256k1.FieldVal
	if overflow := r.SetByteSlice(sig[0:32]); overflow {
		str := "invalid signature: r >= field prime"
		return nil, signatureError(ErrSigRTooBig, str)
	}
	var s secp256k1.ModNScalar
	if overflow := s.SetByteSlice(sig[32:64]); overflow {
		str := "invalid signature: s >= group order"
		return nil, signatureError(ErrSigSTooBig, str)
	}

	// Return the signature.
	var rBytes, sBytes [scalarSize]byte
	r.PutBytes(&rBytes)
	s.PutBytes(&sBytes)
	rBig := encodedBytesToBigInt(&rBytes)
	sBig := encodedBytesToBigInt(&sBytes)
	return &Signature{rBig, sBig}, nil
}

// IsEqual compares this Signature instance to the one passed, returning true
// if both Signatures are equivalent. A signature is equivalent to another, if
// they both have the same scalar value for R and S.
func (sig Signature) IsEqual(otherSig *Signature) bool {
	return sig.r.Cmp(otherSig.r) == 0 &&
		sig.s.Cmp(otherSig.s) == 0
}

// schnorrVerify is the internal function for verification of a secp256k1
// Schnorr signature.
func schnorrVerify(sig *Signature, pubkey *secp256k1.PublicKey, msg []byte) error {
	curve := secp256k1.S256()
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return signatureError(ErrBadInputSize, str)
	}

	if !curve.IsOnCurve(pubkey.X(), pubkey.Y()) {
		str := "pubkey point is not on curve"
		return signatureError(ErrPointNotOnCurve, str)
	}

	rBytes := bigIntToEncodedBytes(sig.r)
	toHash := make([]byte, 0, len(msg)+scalarSize)
	toHash = append(toHash, rBytes[:]...)
	toHash = append(toHash, msg...)
	h := blake256.Sum256(toHash)
	hBig := new(big.Int).SetBytes(h[:])

	// If the hash ends up larger than the order of the curve, abort.
	// Same thing for hash == 0 (as unlikely as that is...).
	if hBig.Cmp(curve.N) >= 0 {
		str := "hash of (R || m) too big"
		return signatureError(ErrSchnorrHashValue, str)
	}
	if hBig.Cmp(bigZero) == 0 {
		str := "hash of (R || m) is zero value"
		return signatureError(ErrSchnorrHashValue, str)
	}

	// We also can't have s greater than the order of the curve.
	if sig.s.Cmp(curve.N) >= 0 {
		str := "s value is too big"
		return signatureError(ErrInputValue, str)
	}

	// r can't be larger than the curve prime.
	if sig.r.Cmp(curve.P) >= 0 {
		str := "given R was greater than curve prime"
		return signatureError(ErrBadSigRNotOnCurve, str)
	}

	// r' = hQ + sG
	sBytes := bigIntToEncodedBytes(sig.s)
	lx, ly := curve.ScalarMult(pubkey.X(), pubkey.Y(), h[:])
	rx, ry := curve.ScalarBaseMult(sBytes[:])
	rlx, rly := curve.Add(lx, ly, rx, ry)

	if rly.Bit(0) == 1 {
		str := "calculated R y-value is odd"
		return signatureError(ErrBadSigRYValue, str)
	}
	if !curve.IsOnCurve(rlx, rly) {
		str := "calculated R point is not on curve"
		return signatureError(ErrBadSigRNotOnCurve, str)
	}
	rlxB := bigIntToEncodedBytes(rlx)

	// r == r' --> valid signature
	if !bytes.Equal(rBytes[:], rlxB[:]) {
		str := "calculated R point was not given R"
		return signatureError(ErrUnequalRValues, str)
	}

	return nil
}

// Verify is the generalized and exported function for the verification of a
// secp256k1 Schnorr signature. BLAKE256 is used as the hashing function.
func (sig *Signature) Verify(msg []byte, pubkey *secp256k1.PublicKey) bool {
	return schnorrVerify(sig, pubkey, msg) == nil
}

// zeroArray zeroes the memory of a scalar array.
func zeroArray(a *[scalarSize]byte) {
	for i := 0; i < scalarSize; i++ {
		a[i] = 0x00
	}
}

// zeroSlice zeroes the memory of a scalar byte slice.
func zeroSlice(s []byte) {
	for i := 0; i < scalarSize; i++ {
		s[i] = 0x00
	}
}

// zeroBigInt zeroes the underlying memory used by the passed big integer.  The
// big integer must not be used after calling this as it changes the internal
// state out from under it which can lead to unpredictable results.
func zeroBigInt(v *big.Int) {
	words := v.Bits()
	for i := 0; i < len(words); i++ {
		words[i] = 0
	}
	v.SetInt64(0)
}

// schnorrSign signs a Schnorr signature using a specified hash function
// and the given nonce, private key, message, and optional public nonce.
// CAVEAT: Lots of variable time algorithms using both the private key and
// k, which can expose the signer to constant time attacks. You have been
// warned! DO NOT use this algorithm where you might have the possibility
// of someone having EM field/cache/etc access.
// Memory management is also kind of sloppy and whether or not your keys
// or nonces can be found in memory later is likely a product of when the
// garbage collector runs.
// TODO Use field elements with constant time algorithms to prevent said
// attacks.
func schnorrSign(msg []byte, ps []byte, k []byte) (*Signature, error) {
	curve := secp256k1.S256()
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return nil, signatureError(ErrBadInputSize, str)
	}
	if len(ps) != scalarSize {
		str := fmt.Sprintf("wrong size for privkey (got %v, want %v)",
			len(ps), scalarSize)
		return nil, signatureError(ErrBadInputSize, str)
	}
	if len(k) != scalarSize {
		str := fmt.Sprintf("wrong size for nonce k (got %v, want %v)",
			len(k), scalarSize)
		return nil, signatureError(ErrBadInputSize, str)
	}

	psBig := new(big.Int).SetBytes(ps)
	bigK := new(big.Int).SetBytes(k)

	if psBig.Cmp(bigZero) == 0 {
		str := "secret scalar is zero"
		return nil, signatureError(ErrInputValue, str)
	}
	if psBig.Cmp(curve.N) >= 0 {
		str := "secret scalar is out of bounds"
		return nil, signatureError(ErrInputValue, str)
	}
	if bigK.Cmp(bigZero) == 0 {
		str := "k scalar is zero"
		return nil, signatureError(ErrInputValue, str)
	}
	if bigK.Cmp(curve.N) >= 0 {
		str := "k scalar is out of bounds"
		return nil, signatureError(ErrInputValue, str)
	}

	// R = kG
	var Rpx, Rpy *big.Int
	Rpx, Rpy = curve.ScalarBaseMult(k)

	// Check if the field element that would be represented by Y is odd.
	// If it is, just keep k in the group order.
	if Rpy.Bit(0) == 1 {
		bigK.Mod(bigK, curve.N)
		bigK.Sub(curve.N, bigK)
	}

	// h = Hash(r || m)
	Rpxb := bigIntToEncodedBytes(Rpx)
	hashInput := make([]byte, 0, scalarSize*2)
	hashInput = append(hashInput, Rpxb[:]...)
	hashInput = append(hashInput, msg...)
	h := blake256.Sum256(hashInput)
	hBig := new(big.Int).SetBytes(h[:])

	// If the hash ends up larger than the order of the curve, abort.
	if hBig.Cmp(curve.N) >= 0 {
		str := "hash of (R || m) too big"
		return nil, signatureError(ErrSchnorrHashValue, str)
	}

	// s = k - hx
	// TODO Speed this up a bunch by using field elements, not
	// big ints. That we multiply the private scalar using big
	// ints is also probably bad because we can only assume the
	// math isn't in constant time, thus opening us up to side
	// channel attacks. Using a constant time field element
	// implementation will fix this.
	sBig := new(big.Int)
	sBig.Mul(hBig, psBig)
	sBig.Sub(bigK, sBig)
	sBig.Mod(sBig, curve.N)

	if sBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("sig s %v is zero", sBig)
		return nil, signatureError(ErrZeroSigS, str)
	}

	// Zero out the private key and nonce when we're done with it.
	zeroBigInt(bigK)
	zeroSlice(k)
	zeroBigInt(psBig)
	zeroSlice(ps)

	return &Signature{Rpx, sBig}, nil
}

// nonceRFC6979 is a local instantiation of deterministic nonce generation
// by the standards of RFC6979.
func nonceRFC6979(privKey []byte, hash []byte, extra []byte, version []byte, extraIterations uint32) []byte {
	k := secp256k1.NonceRFC6979(privKey, hash, extra, version, extraIterations)
	kBytes := k.Bytes()
	defer zeroArray(&kBytes)
	bigK := new(big.Int).SetBytes(kBytes[:])
	defer zeroBigInt(bigK)
	nonce := bigIntToEncodedBytes(bigK)
	return nonce[:]
}

// Sign is the exported version of sign. It uses RFC6979 and Blake256 to
// produce a Schnorr signature.
func Sign(priv *secp256k1.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	// Convert the private scalar to a 32 byte big endian number.
	bigPriv := new(big.Int).SetBytes(priv.Serialize())
	pA := bigIntToEncodedBytes(bigPriv)
	defer zeroArray(pA)

	for iteration := uint32(0); ; iteration++ {
		// Generate a 32-byte scalar to use as a nonce via RFC6979.
		kB := nonceRFC6979(priv.Serialize(), hash, rfc6979ExtraDataV0[:], nil,
			iteration)
		sig, err := schnorrSign(hash, pA[:], kB)
		if err == nil {
			r = sig.r
			s = sig.s
			break
		}

		errTyped, ok := err.(Error)
		if !ok {
			return nil, nil, fmt.Errorf("unknown error type")
		}
		if errTyped.ErrorCode != ErrSchnorrHashValue {
			return nil, nil, err
		}
	}

	return r, s, nil
}
