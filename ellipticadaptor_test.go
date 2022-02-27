// Copyright (c) 2020-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package secp256k1

import (
	"math/big"
	"testing"
)

// TestIsOnCurveAdaptor ensures the IsOnCurve method used to satisfy the
// elliptic.Curve interface works as intended.
func TestIsOnCurveAdaptor(t *testing.T) {
	s256 := S256()
	if !s256.IsOnCurve(s256.Params().Gx, s256.Params().Gy) {
		t.Fatal("generator point does not claim to be on the curve")
	}
}

// isValidAffinePoint returns true if the point (x,y) is on the secp256k1 curve
// or is the point at infinity.
func isValidAffinePoint(x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return true
	}
	return S256().IsOnCurve(x, y)
}

// TestAddAffineAdaptor tests addition of points in affine coordinates via the
// method used to satisfy the elliptic.Curve interface works as intended for
// some edge cases and known good values.
func TestAddAffineAdaptor(t *testing.T) {
	tests := []struct {
		name   string // test description
		x1, y1 string // hex encoded coordinates of first point to add
		x2, y2 string // hex encoded coordinates of second point to add
		x3, y3 string // hex encoded coordinates of expected point
	}{{
		// Addition with the point at infinity (left hand side).
		name: "∞ + P = P",
		x1:   "0",
		y1:   "0",
		x2:   "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
		y2:   "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
		x3:   "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
		y3:   "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
	}, {
		// Addition with the point at infinity (right hand side).
		name: "P + ∞ = P",
		x1:   "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
		y1:   "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
		x2:   "0",
		y2:   "0",
		x3:   "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
		y3:   "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
	}, {
		// Addition with different x values.
		name: "P(x1, y1) + P(x2, y2)",
		x1:   "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
		y1:   "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
		x2:   "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
		y2:   "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
		x3:   "fd5b88c21d3143518d522cd2796f3d726793c88b3e05636bc829448e053fed69",
		y3:   "21cf4f6a5be5ff6380234c50424a970b1f7e718f5eb58f68198c108d642a137f",
	}, {
		// Addition with same x opposite y.
		name: "P(x, y) + P(x, -y) = ∞",
		x1:   "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
		y1:   "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
		x2:   "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
		y2:   "f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
		x3:   "0",
		y3:   "0",
	}, {
		// Addition with same point.
		name: "P(x, y) + P(x, y) = 2P",
		x1:   "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
		y1:   "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
		x2:   "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
		y2:   "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
		x3:   "59477d88ae64a104dbb8d31ec4ce2d91b2fe50fa628fb6a064e22582196b365b",
		y3:   "938dc8c0f13d1e75c987cb1a220501bd614b0d3dd9eb5c639847e1240216e3b6",
	}}

	curve := S256()
	for _, test := range tests {
		// Parse the test data.
		x1, y1 := fromHex(test.x1), fromHex(test.y1)
		x2, y2 := fromHex(test.x2), fromHex(test.y2)
		x3, y3 := fromHex(test.x3), fromHex(test.y3)

		// Ensure the test data is using points that are actually on the curve
		// (or the point at infinity).
		if !isValidAffinePoint(x1, y1) {
			t.Errorf("%s: first point is not on curve", test.name)
			continue
		}
		if !isValidAffinePoint(x2, y2) {
			t.Errorf("%s: second point is not on curve", test.name)
			continue
		}
		if !isValidAffinePoint(x3, y3) {
			t.Errorf("%s: expected point is not on curve", test.name)
			continue
		}

		// Add the two points and ensure the result matches expected.
		rx, ry := curve.Add(x1, y1, x2, y2)
		if rx.Cmp(x3) != 0 || ry.Cmp(y3) != 0 {
			t.Errorf("%s: wrong result\ngot: (%x, %x)\nwant: (%x, %x)",
				test.name, rx, ry, x3, y3)
			continue
		}
	}
}

// TestDoubleAffineAdaptor tests doubling of points in affine coordinates via
// the method used to satisfy the elliptic.Curve interface works as intended for
// some edge cases and known good values.
func TestDoubleAffineAdaptor(t *testing.T) {
	tests := []struct {
		name   string // test description
		x1, y1 string // hex encoded coordinates of point to double
		x3, y3 string // hex encoded coordinates of expected point
	}{{
		// Doubling the point at infinity is still the point at infinity.
		name: "2*∞ = ∞ (point at infinity)",
		x1:   "0",
		y1:   "0",
		x3:   "0",
		y3:   "0",
	}, {
		name: "random point 1",
		x1:   "e41387ffd8baaeeb43c2faa44e141b19790e8ac1f7ff43d480dc132230536f86",
		y1:   "1b88191d430f559896149c86cbcb703193105e3cf3213c0c3556399836a2b899",
		x3:   "88da47a089d333371bd798c548ef7caae76e737c1980b452d367b3cfe3082c19",
		y3:   "3b6f659b09a362821dfcfefdbfbc2e59b935ba081b6c249eb147b3c2100b1bc1",
	}, {
		name: "random point 2",
		x1:   "b3589b5d984f03ef7c80aeae444f919374799edf18d375cab10489a3009cff0c",
		y1:   "c26cf343875b3630e15bccc61202815b5d8f1fd11308934a584a5babe69db36a",
		x3:   "e193860172998751e527bb12563855602a227fc1f612523394da53b746bb2fb1",
		y3:   "2bfcf13d2f5ab8bb5c611fab5ebbed3dc2f057062b39a335224c22f090c04789",
	}, {
		name: "random point 3",
		x1:   "2b31a40fbebe3440d43ac28dba23eee71c62762c3fe3dbd88b4ab82dc6a82340",
		y1:   "9ba7deb02f5c010e217607fd49d58db78ec273371ea828b49891ce2fd74959a1",
		x3:   "2c8d5ef0d343b1a1a48aa336078eadda8481cb048d9305dc4fdf7ee5f65973a2",
		y3:   "bb4914ac729e26d3cd8f8dc8f702f3f4bb7e0e9c5ae43335f6e94c2de6c3dc95",
	}, {
		name: "random point 4",
		x1:   "61c64b760b51981fab54716d5078ab7dffc93730b1d1823477e27c51f6904c7a",
		y1:   "ef6eb16ea1a36af69d7f66524c75a3a5e84c13be8fbc2e811e0563c5405e49bd",
		x3:   "5f0dcdd2595f5ad83318a0f9da481039e36f135005420393e72dfca985b482f4",
		y3:   "a01c849b0837065c1cb481b0932c441f49d1cab1b4b9f355c35173d93f110ae0",
	}}

	curve := S256()
	for _, test := range tests {
		// Parse test data.
		x1, y1 := fromHex(test.x1), fromHex(test.y1)
		x3, y3 := fromHex(test.x3), fromHex(test.y3)

		// Ensure the test data is using points that are actually on
		// the curve (or the point at infinity).
		if !isValidAffinePoint(x1, y1) {
			t.Errorf("%s: first point is not on the curve", test.name)
			continue
		}
		if !isValidAffinePoint(x3, y3) {
			t.Errorf("%s: expected point is not on the curve", test.name)
			continue
		}

		// Double the point and ensure the result matches expected.
		rx, ry := curve.Double(x1, y1)
		if rx.Cmp(x3) != 0 || ry.Cmp(y3) != 0 {
			t.Errorf("%s: wrong result\ngot: (%x, %x)\nwant: (%x, %x)",
				test.name, rx, ry, x3, y3)
			continue
		}
	}
}

// TestScalarBaseMultAdaptor ensures the ScalarBaseMult method used to satisfy
// the elliptic.Curve interface works as intended for some edge cases and known
// good values.
func TestScalarBaseMultAdaptor(t *testing.T) {
	tests := []struct {
		name   string // test description
		k      string // hex encoded scalar
		rx, ry string // hex encoded coordinates of expected point
	}{{
		name: "zero",
		k:    "0000000000000000000000000000000000000000000000000000000000000000",
		rx:   "0000000000000000000000000000000000000000000000000000000000000000",
		ry:   "0000000000000000000000000000000000000000000000000000000000000000",
	}, {
		name: "one (aka 1*G = G)",
		k:    "0000000000000000000000000000000000000000000000000000000000000001",
		rx:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		ry:   "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
	}, {
		name: "group order - 1 (aka -1*G = -G)",
		k:    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		rx:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		ry:   "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
	}, {
		name: "known good point 1",
		k:    "aa5e28d6a97a2479a65527f7290311a3624d4cc0fa1578598ee3c2613bf99522",
		rx:   "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
		ry:   "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
	}, {
		name: "known good point 2",
		k:    "7e2b897b8cebc6361663ad410835639826d590f393d90a9538881735256dfae3",
		rx:   "d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
		ry:   "131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
	}, {
		name: "known good point 3",
		k:    "6461e6df0fe7dfd05329f41bf771b86578143d4dd1f7866fb4ca7e97c5fa945d",
		rx:   "e8aecc370aedd953483719a116711963ce201ac3eb21d3f3257bb48668c6a72f",
		ry:   "c25caf2f0eba1ddb2f0f3f47866299ef907867b7d27e95b3873bf98397b24ee1",
	}, {
		name: "known good point 4",
		k:    "376a3a2cdcd12581efff13ee4ad44c4044b8a0524c42422a7e1e181e4deeccec",
		rx:   "14890e61fcd4b0bd92e5b36c81372ca6fed471ef3aa60a3e415ee4fe987daba1",
		ry:   "297b858d9f752ab42d3bca67ee0eb6dcd1c2b7b0dbe23397e66adc272263f982",
	}, {
		name: "known good point 5",
		k:    "1b22644a7be026548810c378d0b2994eefa6d2b9881803cb02ceff865287d1b9",
		rx:   "f73c65ead01c5126f28f442d087689bfa08e12763e0cec1d35b01751fd735ed3",
		ry:   "f449a8376906482a84ed01479bd18882b919c140d638307f0c0934ba12590bde",
	}}

	curve := S256()
	for _, test := range tests {
		// Parse the test data.
		k := fromHex(test.k)
		xWant, yWant := fromHex(test.rx), fromHex(test.ry)

		// Ensure the test data is using points that are actually on the curve
		// (or the point at infinity).
		if !isValidAffinePoint(xWant, yWant) {
			t.Errorf("%s: expected point is not on curve", test.name)
			continue
		}

		rx, ry := curve.ScalarBaseMult(k.Bytes())
		if rx.Cmp(xWant) != 0 || ry.Cmp(yWant) != 0 {
			t.Errorf("%s: wrong result:\ngot (%x, %x)\nwant (%x, %x)",
				test.name, rx, ry, xWant, yWant)
		}
	}
}

// TestScalarMultAdaptor ensures the ScalarMult method used to satisfy the
// elliptic.Curve interface works as intended for some edge cases and known good
// values.
func TestScalarMultAdaptor(t *testing.T) {
	tests := []struct {
		name   string // test description
		k      string // hex encoded scalar
		x, y   string // hex encoded coordinates of point to multiply
		rx, ry string // hex encoded coordinates of expected point
	}{{
		name: "0*P = ∞ (point at infinity)",
		k:    "0",
		x:    "7e660beda020e9cc20391cef85374576853b0f22b8925d5d81c5845bb834c21e",
		y:    "2d114a5edb320cc9806527d1daf1bbb96a8fedc6f9e8ead421eaef2c7208e409",
		rx:   "0",
		ry:   "0",
	}, {
		name: "1*P = P",
		k:    "1",
		x:    "c00be8830995d1e44f1420dd3b90d3441fb66f6861c84a35f959c495a3be5440",
		y:    "ecf9665e6eba45720de652a340600c7356efe24d228bfe6ea2043e7791c51bb7",
		rx:   "c00be8830995d1e44f1420dd3b90d3441fb66f6861c84a35f959c495a3be5440",
		ry:   "ecf9665e6eba45720de652a340600c7356efe24d228bfe6ea2043e7791c51bb7",
	}, {
		name: "(group order - 1)*P = -P (aka -1*P = -P)",
		k:    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		x:    "74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9",
		y:    "cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08",
		rx:   "74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9",
		ry:   "339ea810e73639c329e6c27c9ce4415ff6c1f6976bd173cc2a8c80276f1f2127",
	}, {
		name: "(group order - 1)*-P = P (aka -1*-P = -P, with P from prev test)",
		k:    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		x:    "74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9",
		y:    "339ea810e73639c329e6c27c9ce4415ff6c1f6976bd173cc2a8c80276f1f2127",
		rx:   "74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9",
		ry:   "cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08",
	}, {
		name: "known good point from base mult tests (aka k*G)",
		k:    "aa5e28d6a97a2479a65527f7290311a3624d4cc0fa1578598ee3c2613bf99522",
		x:    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		y:    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		rx:   "34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
		ry:   "0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
	}, {
		name: "known good result 1",
		k:    "7e2b897b8cebc6361663ad410835639826d590f393d90a9538881735256dfae3",
		x:    "1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5",
		y:    "b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396",
		rx:   "6951f3b50aafbc63e21707dd53623b7f42badd633a0567ef1b37f6e42a4237ad",
		ry:   "9c930796a49110122fbfdedc36418af726197ed950b783a2d29058f8c02130de",
	}, {
		name: "known good result 2",
		k:    "6461e6df0fe7dfd05329f41bf771b86578143d4dd1f7866fb4ca7e97c5fa945d",
		x:    "659214ac1a1790023f53c4cf55a0a63b9e20c1151efa971215b395a558aa151",
		y:    "b126363aa4243d2759320a356230569a4eea355d9dabd94ed7f4590701e5364d",
		rx:   "4ffad856833396ef753c0bd4ea40319295f107c476793df0adac2caea53b3df4",
		ry:   "586fa6b1e9a3ff7df8a2b9b3698badcf40aa06af5600fefc56dd8ae4db5451c5",
	}, {
		name: "known good result 3",
		k:    "376a3a2cdcd12581efff13ee4ad44c4044b8a0524c42422a7e1e181e4deeccec",
		x:    "3f0e80e574456d8f8fa64e044b2eb72ea22eb53fe1efe3a443933aca7f8cb0e3",
		y:    "cb66d7d7296cbc91e90b9c08485d01b39501253aa65b53a4cb0289e2ea5f404f",
		rx:   "35ae6480b18e48070709d9276ed97a50c6ee1fc05ac44386c85826533233d28f",
		ry:   "f88abee3efabd95e80ce8c664bbc3d4d12b24e1a0f4d2b98ba6542789c6715fd",
	}, {
		name: "known good result 4",
		k:    "1b22644a7be026548810c378d0b2994eefa6d2b9881803cb02ceff865287d1b9",
		x:    "d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
		y:    "581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58",
		rx:   "cca7f9a4b0d379c31c438050e163a8945f2f910498bd3b545be20ed862bd6cd9",
		ry:   "cfc7bbf37bef62da6e5753ed419168fa1376a3fe949c139a8dd0f5303f4ae947",
	}, {
		name: "known good result 5",
		k:    "7f5b2cb4b43840c75e4afad83d792e1965d8c21c1109505f45c7d46df422d73e",
		x:    "bce74de6d5f98dc027740c2bbff05b6aafe5fd8d103f827e48894a2bd3460117",
		y:    "5bea1fa17a41b115525a3e7dbf0d8d5a4f7ce5c6fc73a6f4f216512417c9f6b4",
		rx:   "3d96b9290fe6c4f2d62fe2175f4333907d0c3637fada1010b45c7d80690e16de",
		ry:   "d59c0e8192d7fbd4846172d6479630b751cd03d0d9be0dca2759c6212b70575d",
	}, {
		// From btcd issue #709.
		name: "early implementation regression point",
		k:    "a2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba219b51835b55cc30ebfe2f6599bc56f58",
		x:    "000000000000000000000000000000000000000000000000000000000000002c",
		y:    "420e7a99bba18a9d3952597510fd2b6728cfeafc21a4e73951091d4d8ddbe94e",
		rx:   "a2112dcdfbcd10ae1133a358de7b82db68e0a3eb4b492cc8268d1e7118c98788",
		ry:   "27fc7463b7bb3c5f98ecf2c84a6272bb1681ed553d92c69f2dfe25a9f9fd3836",
	}}

	curve := S256()
	for _, test := range tests {
		// Parse the test data.
		k := fromHex(test.k)
		x, y := fromHex(test.x), fromHex(test.y)
		xWant, yWant := fromHex(test.rx), fromHex(test.ry)

		// Ensure the test data is using points that are actually on the curve
		// (or the point at infinity).
		if !isValidAffinePoint(x, y) {
			t.Errorf("%s: point is not on curve", test.name)
			continue
		}
		if !isValidAffinePoint(xWant, yWant) {
			t.Errorf("%s: expected point is not on curve", test.name)
			continue
		}

		// Perform scalar point multiplication ensure the result matches
		// expected.
		rx, ry := curve.ScalarMult(x, y, k.Bytes())
		if rx.Cmp(xWant) != 0 || ry.Cmp(yWant) != 0 {
			t.Errorf("%s: wrong result\ngot: (%x, %x)\nwant: (%x, %x)",
				test.name, rx, ry, xWant, yWant)
		}
	}
}
