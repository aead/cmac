// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package cmac

import (
	"bytes"
	"encoding/hex"
	"testing"
	"unsafe"
)

func unalignBytes(in []byte) []byte {
	out := make([]byte, len(in)+1)
	if uintptr(unsafe.Pointer(&out[0]))&(unsafe.Alignof(uint32(0))-1) == 0 {
		out = out[1:]
	} else {
		out = out[:len(in)]
	}
	copy(out, in)
	return out
}

func testXOR(t *testing.T, dSize, sSize int, unalign bool) {
	dst0, src := make([]byte, dSize), make([]byte, sSize)
	dst1 := make([]byte, dSize)

	if unalign {
		src = unalignBytes(src)
	}

	for i := 0; i < len(src); i++ {
		src[i] = byte(i)
		dst0[i], dst1[i] = byte(i*i), byte(i*i)
		dst0[i] ^= src[i]
	}
	xor(dst1, src)

	if !bytes.Equal(dst0, dst1) {
		t.Fatalf("xor failed:\nexpected: %s\ngot: %s", hex.EncodeToString(dst0), hex.EncodeToString(dst1))
	}
}

func TestXOR(t *testing.T) {
	testXOR(t, 0, 0, true)
	testXOR(t, 0, 0, false)
	testXOR(t, 64, 64, true)
	testXOR(t, 64, 64, false)
	testXOR(t, 65, 64, true)
	testXOR(t, 65, 64, false)
	testXOR(t, 16, 16, true)
	testXOR(t, 16, 16, false)
}

func benchmarkXOR(b *testing.B, size int, unalign bool) {
	dst, src := make([]byte, size), make([]byte, size)
	if unalign {
		src = unalignBytes(src)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xor(dst, src)
	}
}

func BenchmarkXOR_64(b *testing.B)          { benchmarkXOR(b, 64, false) }
func BenchmarkXOR_1K(b *testing.B)          { benchmarkXOR(b, 1024, false) }
func BenchmarkXORUnaligned_64(b *testing.B) { benchmarkXOR(b, 64, true) }
func BenchmarkXORUnaligned_1K(b *testing.B) { benchmarkXOR(b, 1024, true) }
