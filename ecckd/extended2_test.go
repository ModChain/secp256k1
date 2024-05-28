package ecckd

import (
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/ModChain/secp256k1"
)

func TestImportedPubKey(t *testing.T) {
	pubkey, _ := base64.RawURLEncoding.DecodeString("AtKC5Y9pZSWAwdn9zMbloDkcNuZWGJvsmaOSsAI2eVfT")
	chainCode := make([]byte, 32) // null chaincode for tests

	key, err := secp256k1.ParsePubKey(pubkey)
	if err != nil {
		t.Fatalf("failed to parse pubkey: %s", err)
		return
	}

	ek, err := FromPublicKey(key.ToECDSA(), chainCode)
	if err != nil {
		t.Fatalf("failed to initialize EK: %s", err)
		return
	}

	var il *big.Int
	il, ek, err = ek.DeriveWithIL([]uint32{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("failed to derive: %s", err)
		return
	}

	if ek.String() != "xpub6DcxRE8ZghewQma1sWs1QwYdxPVMtssCS1ET597UoAVxU4oXVmex6KLGMppuosy8FAFWvQxHKEjQ99rS7gXiZzjWXbm8PpoubcXYwgUk8ts" {
		t.Errorf("ek bad public key %s", ek)
	}

	if il.String() != "94659408799543855417706076338932055351028645711792081993515207436011379608109" {
		t.Errorf("il bad value %s", il)
	}
}
