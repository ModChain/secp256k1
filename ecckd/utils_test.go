package ecckd

import (
	"bytes"
	"testing"
)

func TestPaddedAppend(t *testing.T) {
	tests := []struct {
		name string
		size int
		dst  []byte
		src  []byte
		want []byte
	}{
		{
			name: "no padding needed",
			size: 3,
			dst:  []byte{0xaa},
			src:  []byte{1, 2, 3},
			want: []byte{0xaa, 1, 2, 3},
		},
		{
			name: "padding needed with capacity",
			size: 5,
			dst:  make([]byte, 1, 10),
			src:  []byte{1, 2, 3},
			want: append([]byte{0, 0, 0}, 1, 2, 3),
		},
		{
			name: "padding needed without capacity (reallocation path)",
			size: 5,
			dst:  []byte{0xbb},
			src:  []byte{1, 2, 3},
			want: []byte{0xbb, 0, 0, 1, 2, 3},
		},
		{
			name: "empty src with size",
			size: 3,
			dst:  []byte{0xcc},
			src:  []byte{},
			want: []byte{0xcc, 0, 0, 0},
		},
		{
			name: "src equals size",
			size: 2,
			dst:  []byte{0xdd},
			src:  []byte{1, 2},
			want: []byte{0xdd, 1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For the "padding needed with capacity" test, set dst[0]
			if tt.name == "padding needed with capacity" {
				tt.dst[0] = 0
			}
			got := paddedAppend(tt.size, tt.dst, tt.src)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("paddedAppend() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestPaddedAppendReallocation(t *testing.T) {
	// This specifically tests the bug fix where ndst was not assigned back
	// to dst in the reallocation branch, causing zero padding to be lost.
	dst := []byte{0x01}                      // len=1, cap=1, no room for padding
	src := []byte{0x42}                       // 1 byte
	result := paddedAppend(4, dst, src)       // needs 3 bytes of zero padding + src
	expected := []byte{0x01, 0, 0, 0, 0x42}  // dst + 3 zero pad + src

	if !bytes.Equal(result, expected) {
		t.Errorf("paddedAppend reallocation: got %x, want %x", result, expected)
	}
}
