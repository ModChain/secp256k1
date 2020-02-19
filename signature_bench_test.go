// Copyright 2013-2016 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package secp256k1

import (
	"testing"
)

// BenchmarkSigVerify benchmarks how long it takes the secp256k1 curve to
// verify signatures.
func BenchmarkSigVerify(b *testing.B) {
	b.StopTimer()
	// Randomly generated keypair.
	// Private key: 9e0699c91ca1e3b7e3c9ba71eb71c89890872be97576010fe593fbf3fd57e66d
	pubKey := PublicKey{
		X: fromHex("d2e670a19c6d753d1a6d8b20bd045df8a08fb162cf508956c31268c6d81ffdab"),
		Y: fromHex("ab65528eefbb8057aa85d597258a3fbd481a24633bc9b47a9aa045c91371de52"),
	}

	// Double sha256 of []byte{0x01, 0x02, 0x03, 0x04}
	msgHash := fromHex("8de472e2399610baaa7f84840547cd409434e31f5d3bd71e4d947f283874f9c0")
	sig := Signature{
		r: fromHex("fef45d2892953aa5bbcdb057b5e98b208f1617a7498af7eb765574e29b5d9c2c"),
		s: fromHex("d47563f52aac6b04b55de236b7c515eb9311757db01e02cff079c3ca6efb063f"),
	}

	if !sig.Verify(msgHash.Bytes(), &pubKey) {
		b.Errorf("Signature failed to verify")
		return
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		sig.Verify(msgHash.Bytes(), &pubKey)
	}
}

// BenchmarkSign benchmarks how long it takes to sign a message.
func BenchmarkSign(b *testing.B) {
	// Randomly generated keypair.
	d := new(ModNScalar).SetHex("9e0699c91ca1e3b7e3c9ba71eb71c89890872be97576010fe593fbf3fd57e66d")
	privKey := NewPrivateKey(d)

	// blake256 of []byte{0x01, 0x02, 0x03, 0x04}.
	msgHash := hexToBytes("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signRFC6979(privKey, msgHash)
	}
}

// BenchmarkSigSerialize benchmarks how long it takes to serialize a typical
// signature with the strict DER encoding.
func BenchmarkSigSerialize(b *testing.B) {
	// Randomly generated keypair.
	// Private key: 9e0699c91ca1e3b7e3c9ba71eb71c89890872be97576010fe593fbf3fd57e66d
	// Signature for double sha256 of []byte{0x01, 0x02, 0x03, 0x04}.
	sig := Signature{
		r: fromHex("fef45d2892953aa5bbcdb057b5e98b208f1617a7498af7eb765574e29b5d9c2c"),
		s: fromHex("d47563f52aac6b04b55de236b7c515eb9311757db01e02cff079c3ca6efb063f"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig.Serialize()
	}
}

// BenchmarkNonceRFC6979 benchmarks how long it takes to generate a
// deterministic nonce according to RFC6979.
func BenchmarkNonceRFC6979(b *testing.B) {
	// Randomly generated keypair.
	// Private key: 9e0699c91ca1e3b7e3c9ba71eb71c89890872be97576010fe593fbf3fd57e66d
	// X: d2e670a19c6d753d1a6d8b20bd045df8a08fb162cf508956c31268c6d81ffdab
	// Y: ab65528eefbb8057aa85d597258a3fbd481a24633bc9b47a9aa045c91371de52
	privKeyStr := "9e0699c91ca1e3b7e3c9ba71eb71c89890872be97576010fe593fbf3fd57e66d"
	privKey := hexToBytes(privKeyStr)

	// BLAKE-256 of []byte{0x01, 0x02, 0x03, 0x04}.
	msgHash := hexToBytes("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")

	b.ReportAllocs()
	b.ResetTimer()
	var noElideNonce *ModNScalar
	for i := 0; i < b.N; i++ {
		noElideNonce = NonceRFC6979(privKey, msgHash, nil, nil, 0)
	}
	_ = noElideNonce
}
