package ecckd

const (
	HardenedBit = 0x80000000 // hardened keys do not allow derivation of public keys

	// serializedKeyLen is the length of a serialized public or private
	// extended key.  It consists of 4 bytes version, 1 byte depth, 4 bytes
	// fingerprint, 4 bytes child number, 32 bytes chain code, and 33 bytes
	// public/private key data.
	serializedKeyLen = 4 + 1 + 4 + 4 + 32 + 33 // 78 bytes
)
