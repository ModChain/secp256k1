// Copyright 2015 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package secp256k1

import (
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"io/ioutil"
	"strings"
	"sync"
)

//go:generate go run -tags gensecp256k1 genprecomps.go

// bytePointTable describes a table used to house pre-computed values for
// accelerating scalar base multiplication.
type bytePointTable [32][256][3]FieldVal

// s256BytePoints houses pre-computed values used to accelerate scalar base
// multiplication such that they are only loaded on first use.
var s256BytePoints = func() func() *bytePointTable {
	// mustLoadBytePoints decompresses and deserializes the pre-computed byte
	// points used to accelerate scalar base multiplication for the secp256k1
	// curve.
	//
	// This approach is used since it allows the compile to use significantly
	// less ram and be performed much faster than it is with hard-coding the
	// final in-memory data structure.  At the same time, it is quite fast to
	// generate the in-memory data structure on first use with this approach
	// versus computing the table.
	//
	// It will panic on any errors because the data is hard coded and thus any
	// errors means something is wrong in the source code.
	var data *bytePointTable
	mustLoadBytePoints := func() {
		// There will be no byte points to load when generating them.
		bp := compressedBytePoints
		if len(bp) == 0 {
			return
		}

		// Decompress the pre-computed table used to accelerate scalar base
		// multiplication.
		decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(bp))
		r, err := zlib.NewReader(decoder)
		if err != nil {
			panic(err)
		}
		serialized, err := ioutil.ReadAll(r)
		if err != nil {
			panic(err)
		}

		// Deserialize the precomputed byte points and set the memory table to
		// them.
		offset := 0
		var bytePoints bytePointTable
		for byteNum := 0; byteNum < len(bytePoints); byteNum++ {
			// All points in this window.
			for i := 0; i < len(bytePoints[byteNum]); i++ {
				px := &bytePoints[byteNum][i][0]
				py := &bytePoints[byteNum][i][1]
				pz := &bytePoints[byteNum][i][2]
				for i := 0; i < len(px.n); i++ {
					px.n[i] = binary.LittleEndian.Uint32(serialized[offset:])
					offset += 4
				}
				for i := 0; i < len(py.n); i++ {
					py.n[i] = binary.LittleEndian.Uint32(serialized[offset:])
					offset += 4
				}
				for i := 0; i < len(pz.n); i++ {
					pz.n[i] = binary.LittleEndian.Uint32(serialized[offset:])
					offset += 4
				}
			}
		}
		data = &bytePoints
	}

	// Return a closure that initializes the data on first access.  This is done
	// because the table takes a non-trivial amount of memory and initializing
	// it unconditionally would cause anything that imports the package, either
	// directly, or indirectly via transitive deps, to use that memory even if
	// the caller never accesses any parts of the package that actually needs
	// access to it.
	var loadBytePointsOnce sync.Once
	return func() *bytePointTable {
		loadBytePointsOnce.Do(mustLoadBytePoints)
		return data
	}
}()
