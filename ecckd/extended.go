package ecckd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ModChain/base58"
	"github.com/ModChain/secp256k1"
)

type ExtendedKey struct {
	Version     KeyVersion
	Depth       uint8
	Fingerprint [4]byte
	ChildNumber uint32 // ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
	KeyData     []byte // 33 bytes, the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
	ChainCode   []byte // 32 bytes, the chain code
	curve       elliptic.Curve
}

// FromBitcoinSeed returns a master node for a bitcoin wallet
func FromBitcoinSeed(seed []byte) (*ExtendedKey, error) {
	return FromSeed(seed, []byte("Bitcoin seed"))
}

func FromSeed(seed, masterSecret []byte) (*ExtendedKey, error) {
	key, chainCode, err := hmacCKD(seed, masterSecret)
	if err != nil {
		return nil, err
	}

	res := &ExtendedKey{
		Version:     BitcoinMainnetPrivate,
		Depth:       0,
		Fingerprint: [4]byte{0, 0, 0, 0},
		ChildNumber: 0,
		KeyData:     key,
		ChainCode:   chainCode,
		curve:       secp256k1.S256(),
	}
	return res, nil
}

func FromString(str string) (*ExtendedKey, error) {
	bin, err := base58.Bitcoin.Decode(str)
	if err != nil {
		return nil, err
	}

	e := &ExtendedKey{}
	return e, e.UnmarshalBinary(bin)
}

// FromPublicKey will initialize an ExtendedKey with the provided ecdsa.PublicKey.
func FromPublicKey(pubkey *ecdsa.PublicKey, chainCode []byte) (*ExtendedKey, error) {
	if len(chainCode) != 32 {
		return nil, errors.New("invalid chainCode length")
	}

	res := &ExtendedKey{
		Version:     BitcoinMainnetPublic, // we don't care that much about version since it's not used in the calculations
		Fingerprint: [4]byte{0, 0, 0, 0},
		ChildNumber: 0,
		Depth:       0,
		KeyData:     serializeCompressedEcdsa(pubkey),
		ChainCode:   chainCode,
		curve:       pubkey.Curve,
	}
	return res, nil
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

func isEven(n *big.Int) bool {
	return new(big.Int).And(n, bigOne).Cmp(bigZero) == 0
}

func serializeCompressedEcdsa(k *ecdsa.PublicKey) []byte {
	format := secp256k1.PubKeyFormatCompressedEven
	if !isEven(k.Y) {
		format = secp256k1.PubKeyFormatCompressedOdd
	}

	b := make([]byte, 33)
	b[0] = format
	k.X.FillBytes(b[1:])
	return b
}

func (k *ExtendedKey) IsPrivate() bool {
	return k.Version.IsPrivate()
}

// Child derives extended key at a given index i.
// If parent is private, then derived key is also private. If parent is public, then derived is public.
//
// If i >= HardenedKeyStart, then hardened key is generated.
// You can only generate hardened keys from private parent keys.
// If you try generating hardened key form public parent key, ErrDerivingHardenedFromPublic is returned.
//
// There are four CKD (child key derivation) scenarios:
// 1) Private extended key -> Hardened child private extended key
// 2) Private extended key -> Non-hardened child private extended key
// 3) Public extended key -> Non-hardened child public extended key
// 4) Public extended key -> Hardened child public extended key (INVALID!)
func (k *ExtendedKey) Child(i uint32) (*ExtendedKey, error) {
	_, ek, err := k.ChildWithIL(i)
	return ek, err
}

// ChildWithIL derives extended key at a given index i, and returns IL (I left) too.
func (k *ExtendedKey) ChildWithIL(i uint32) (*big.Int, *ExtendedKey, error) {
	if k.Depth == 0xff {
		return nil, nil, ErrMaxDepthExceeded
	}

	// A hardened child may not be created from a public extended key (Case #4).
	isChildHardened := i&HardenedBit == HardenedBit
	if !k.IsPrivate() && isChildHardened {
		return nil, nil, ErrDerivingHardenedFromPublic
	}

	keyLen := 33
	seed := make([]byte, keyLen+4)
	if isChildHardened {
		// Case #1: 0x00 || ser256(parentKey) || ser32(i)
		copy(seed[1:], k.KeyData) // 0x00 || ser256(parentKey)
	} else {
		// Case #2 and #3: serP(parentPubKey) || ser32(i)
		copy(seed, k.pubKeyBytes())
	}
	binary.BigEndian.PutUint32(seed[keyLen:], i)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	// secretKey = IL, chainCode = IR
	secretKey, chainCode, err := hmacCKD(seed, k.ChainCode)
	if err != nil {
		return nil, nil, err
	}

	il := new(big.Int).SetBytes(secretKey)

	child := &ExtendedKey{
		ChainCode:   chainCode,
		Depth:       k.Depth + 1,
		ChildNumber: i,
		curve:       k.curve,
		// The fingerprint for the derived child is the first 4 bytes of parent's
	}
	copy(child.Fingerprint[:], rmd160sha256(k.pubKeyBytes()))

	if k.IsPrivate() {
		// Case #1 or #2: childKey = parse256(IL) + parentKey
		parentKeyBigInt := new(big.Int).SetBytes(k.KeyData)
		keyBigInt := new(big.Int).SetBytes(secretKey)
		keyBigInt.Add(keyBigInt, parentKeyBigInt)
		keyBigInt.Mod(keyBigInt, k.curve.Params().N)

		// Make sure that child.KeyData is 32 bytes of data even if the value is represented with less bytes.
		// When we derive a child of this key, we call splitHMAC that does a sha512 of a seed that is:
		// - 1 byte with 0x00
		// - 32 bytes for the key data
		// - 4 bytes for the child key index
		// If we don't padd the KeyData, it will be shifted to left in that 32 bytes space
		// generating a different seed and different child key.
		// This part fixes a bug we had previously and described at:
		// https://medium.com/@alexberegszaszi/why-do-my-bip32-wallets-disagree-6f3254cc5846#.86inuifuq
		keyData := keyBigInt.Bytes()
		if len(keyData) < 32 {
			extra := make([]byte, 32-len(keyData))
			keyData = append(extra, keyData...)
		}

		child.KeyData = keyData
		child.Version = k.Version
	} else {
		// Case #3: childKey = serP(point(parse256(IL)) + parentKey)

		// Calculate the corresponding intermediate public key for intermediate private key.
		keyx, keyy := k.curve.ScalarBaseMult(secretKey)
		if keyx.Sign() == 0 || keyy.Sign() == 0 {
			return nil, nil, ErrInvalidKey
		}

		// Convert the serialized compressed parent public key into X and Y coordinates
		// so it can be added to the intermediate public key.
		pubKey, err := secp256k1.ParsePubKey(k.KeyData)
		if err != nil {
			return nil, nil, err
		}

		// childKey = serP(point(parse256(IL)) + parentKey)
		childX, childY := k.curve.Add(keyx, keyy, pubKey.X(), pubKey.Y())
		pk := secp256k1.NewPublicKey(asFV(childX), asFV(childY))
		child.KeyData = pk.SerializeCompressed()
		child.Version = k.Version.ToPublic()
	}
	return il, child, nil
}

// Derive returns a derived child key at a given path
func (k *ExtendedKey) Derive(path []uint32) (*ExtendedKey, error) {
	var err error

	extKey := k
	for _, i := range path {
		extKey, err = extKey.Child(i)
		if err != nil {
			return nil, fmt.Errorf("error deriving child: %w", err)
		}
	}

	return extKey, nil
}

// DeriveWithIL returns a derived child key at a given path
func (k *ExtendedKey) DeriveWithIL(path []uint32) (*big.Int, *ExtendedKey, error) {
	var err error
	var il *big.Int
	mod := k.curve.Params().N

	extKey := k
	for _, i := range path {
		var curIl *big.Int

		curIl, extKey, err = extKey.ChildWithIL(i)
		if err != nil {
			return nil, nil, fmt.Errorf("error deriving child: %w", err)
		}

		if il == nil {
			il = curIl
		} else {
			il = il.Add(il, curIl)
			il = il.Mod(il, mod)
		}
	}

	return il, extKey, nil
}

// Public returns a new extended public key from a give extended private key.
// If the input extended key is already public, it will be returned unaltered.
func (k *ExtendedKey) Public() (*ExtendedKey, error) {
	// Already an extended public key.
	if !k.IsPrivate() {
		return k, nil
	}

	// Convert it to an extended public key.  The key for the new extended
	// key will simply be the pubkey of the current extended private key.
	return &ExtendedKey{
		Version:     k.Version.ToPublic(),
		KeyData:     k.pubKeyBytes(),
		ChainCode:   k.ChainCode,
		Fingerprint: k.Fingerprint,
		Depth:       k.Depth,
		ChildNumber: k.ChildNumber,
		curve:       k.curve,
	}, nil
}

// MarshalBinary encodes the key in standard format that can be base58 encoded for humans
func (k *ExtendedKey) MarshalBinary() ([]byte, error) {
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.ChildNumber)

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)
	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.Version[:]...)
	serializedBytes = append(serializedBytes, k.Depth)
	serializedBytes = append(serializedBytes, k.Fingerprint[:]...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.ChainCode...)
	if k.IsPrivate() {
		serializedBytes = append(serializedBytes, 0x00)
		serializedBytes = paddedAppend(32, serializedBytes, k.KeyData)
	} else {
		serializedBytes = append(serializedBytes, k.pubKeyBytes()...)
	}

	checkSum := doubleSha256(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return serializedBytes, nil
}

func (k *ExtendedKey) String() string {
	bin, _ := k.MarshalBinary()
	return base58.Bitcoin.Encode(bin)
}

// pubKeyBytes returns bytes for the serialized compressed public key associated
// with this extended key in an efficient manner including memoization as
// necessary.
//
// When the extended key is already a public key, the key is simply returned as
// is since it's already in the correct form.  However, when the extended key is
// a private key, the public key will be calculated and memoized so future
// accesses can simply return the cached result.
func (k *ExtendedKey) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.IsPrivate() {
		return k.KeyData
	}

	pkx, pky := k.curve.ScalarBaseMult(k.KeyData)
	return serializeCompressedEcdsa(&ecdsa.PublicKey{Curve: k.curve, X: pkx, Y: pky})
}

// ToECDSA returns the key data as ecdsa.PrivateKey
func (k *ExtendedKey) ToECDSA() *ecdsa.PrivateKey {
	privKey := secp256k1.PrivKeyFromBytes(k.KeyData)
	return privKey.ToECDSA()
}

func (k *ExtendedKey) UnmarshalBinary(data []byte) error {
	if len(data) != serializedKeyLen+4 {
		return ErrInvalidKeyLen
	}

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)

	// Split the payload and checksum up and ensure the checksum matches.
	payload := data[:len(data)-4]
	checkSum := data[len(data)-4:]
	expectedCheckSum := doubleSha256(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return ErrBadChecksum
	}

	// Deserialize each of the payload fields.
	var version KeyVersion
	copy(version[:], payload[:4])
	depth := payload[4:5][0]
	var fingerprint [4]byte
	copy(fingerprint[:], payload[5:9])
	childNumber := binary.BigEndian.Uint32(payload[9:13])
	chainCode := payload[13:45]
	keyData := payload[45:78]

	// The key data is a private key if it starts with 0x00.  Serialized
	// compressed pubkeys either start with 0x02 or 0x03.
	isPrivate := keyData[0] == 0x00
	if isPrivate != version.IsPrivate() {
		return ErrInvalidPrivateFlag
	}

	if isPrivate {
		// Ensure the private key is valid.  It must be within the range
		// of the order of the secp256k1 curve and not be 0.
		keyData = keyData[1:]
		keyNum := new(big.Int).SetBytes(keyData)
		if keyNum.Cmp(secp256k1.S256().N) >= 0 || keyNum.Sign() == 0 {
			return ErrInvalidSeed
		}
	} else {
		// Ensure the public key parses correctly and is actually on the
		// secp256k1 curve.
		_, err := secp256k1.ParsePubKey(keyData)
		if err != nil {
			return err
		}
	}

	k.Version = version
	k.KeyData = keyData
	k.ChainCode = chainCode
	k.Fingerprint = fingerprint
	k.Depth = depth
	k.ChildNumber = childNumber
	k.curve = secp256k1.S256()
	return nil
}
