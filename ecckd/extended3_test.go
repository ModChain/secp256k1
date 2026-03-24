package ecckd

import (
	"testing"
)

func TestFromSeedValidation(t *testing.T) {
	// Seed too short (< 16 bytes)
	_, err := FromBitcoinSeed(make([]byte, 15))
	if err != ErrInvalidSeed {
		t.Errorf("expected ErrInvalidSeed for short seed, got %v", err)
	}

	// Seed too long (> 64 bytes)
	_, err = FromBitcoinSeed(make([]byte, 65))
	if err != ErrInvalidSeed {
		t.Errorf("expected ErrInvalidSeed for long seed, got %v", err)
	}

	// Minimum valid seed length (16 bytes)
	_, err = FromBitcoinSeed(make([]byte, 16))
	if err != nil {
		t.Errorf("unexpected error for 16-byte seed: %v", err)
	}

	// Maximum valid seed length (64 bytes)
	_, err = FromBitcoinSeed(make([]byte, 64))
	if err != nil {
		t.Errorf("unexpected error for 64-byte seed: %v", err)
	}

	// Empty seed
	_, err = FromBitcoinSeed(nil)
	if err != ErrInvalidSeed {
		t.Errorf("expected ErrInvalidSeed for nil seed, got %v", err)
	}
}

func TestFromStringReturnsNilOnError(t *testing.T) {
	// Invalid base58 string
	key, err := FromString("invalidbase58!!!")
	if err == nil {
		t.Error("expected error for invalid string")
	}
	if key != nil {
		t.Error("expected nil key on error")
	}
}

func TestToECDSAPublicKeyError(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 1
	ek, err := FromBitcoinSeed(seed)
	if err != nil {
		t.Fatalf("FromBitcoinSeed: %v", err)
	}

	// Private key should work
	_, err = ek.ToECDSA()
	if err != nil {
		t.Errorf("ToECDSA on private key should not error: %v", err)
	}

	// Public key should return error (not panic)
	pub, err := ek.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	_, err = pub.ToECDSA()
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for public key ToECDSA, got %v", err)
	}
}
