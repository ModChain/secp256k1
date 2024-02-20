package ecckd

type KeyVersion [4]byte

var (
	BitcoinMainnetPublic  = KeyVersion{0x04, 0x88, 0xb2, 0x1e}
	BitcoinMainnetPrivate = KeyVersion{0x04, 0x88, 0xad, 0xe4}
	BitcoinTestnetPublic  = KeyVersion{0x04, 0x35, 0x87, 0xcf}
	BitcoinTestnetPrivate = KeyVersion{0x04, 0x35, 0x83, 0x94}
)

// IsPrivate returns true if the version is for a private key
func (kv KeyVersion) IsPrivate() bool {
	switch kv {
	case BitcoinMainnetPrivate, BitcoinTestnetPrivate:
		return true
	}
	return false
}

func (kv KeyVersion) ToPublic() KeyVersion {
	switch kv {
	case BitcoinMainnetPrivate:
		return BitcoinMainnetPublic
	case BitcoinTestnetPrivate:
		return BitcoinTestnetPublic
	}
	return kv
}
