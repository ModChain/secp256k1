package ecckd

import (
	"errors"
)

var (
	ErrInvalidKey                 = errors.New("key is invalid")
	ErrInvalidKeyPurpose          = errors.New("key purpose is invalid")
	ErrInvalidSeed                = errors.New("seed is invalid")
	ErrDerivingHardenedFromPublic = errors.New("cannot derive a hardened key from public key")
	ErrBadChecksum                = errors.New("bad extended key checksum")
	ErrInvalidKeyLen              = errors.New("serialized extended key length is invalid")
	ErrDerivingChild              = errors.New("error deriving child key")
	ErrInvalidMasterKey           = errors.New("invalid master key supplied")
	ErrMaxDepthExceeded           = errors.New("max depth exceeded")
	ErrInvalidPrivateFlag         = errors.New("key private flag does not match version")
)
