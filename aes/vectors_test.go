// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Test vectors for CMAC-AES from NIST
// http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
// Appendix D
var testVectors = []struct {
	key, msg, hash string
	tagsize        int
}{
	// AES-128 vectors
	{
		key:     "2b7e151628aed2a6abf7158809cf4f3c",
		msg:     "",
		hash:    "bb1d6929e95937287fa37d129b756746",
		tagsize: 16,
	},
	{
		key:     "2b7e151628aed2a6abf7158809cf4f3c",
		msg:     "6bc1bee22e409f96e93d7e117393172a",
		hash:    "070a16b46b4d4144f79bdd9dd04a287c",
		tagsize: 16,
	},
	{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		msg: "6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411",
		hash:    "dfa66747de9ae63030ca32611497c827",
		tagsize: 16,
	},
	{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		msg: "6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411",
		hash:    "dfa66747de9ae63030ca32611497c827",
		tagsize: 16,
	},
	{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		msg: "6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411",
		hash:    "dfa66747de9ae63030ca3261",
		tagsize: 12,
	},
	// AES-256 vectors
	{
		key: "603deb1015ca71be2b73aef0857d7781" +
			"1f352c073b6108d72d9810a30914dff4",
		msg:     "",
		hash:    "028962f61b7bf89efc6b551f4667d983",
		tagsize: 16,
	},
	{
		key: "603deb1015ca71be2b73aef0857d7781" +
			"1f352c073b6108d72d9810a30914dff4",
		msg:     "6bc1bee22e409f96e93d7e117393172a",
		hash:    "28a7023f452e8f82bd4bf28d8c37c35c",
		tagsize: 16,
	},
	{
		key: "603deb1015ca71be2b73aef0857d7781" +
			"1f352c073b6108d72d9810a30914dff4",
		msg: "6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411",
		hash:    "aaf3d8f1de5640c232f5b169b9c911e6",
		tagsize: 16,
	},
	{
		key: "603deb1015ca71be2b73aef0857d7781" +
			"1f352c073b6108d72d9810a30914dff4",
		msg: "6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411",
		hash:    "aaf3d8f1de5640c232f5b169",
		tagsize: 12,
	},
}

func TestVectors(t *testing.T) {
	for i, v := range testVectors {
		key := fromHex(v.key)
		msg := fromHex(v.msg)
		hash := fromHex(v.hash)

		h, err := NewWithTagSize(key, v.tagsize)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create CMac instance: %s", i, err)
		}
		_, err = h.Write(msg)
		if err != nil {
			t.Fatalf("Test vector %d: CMac write failed: %s", i, err)
		}
		sum := h.Sum(nil)
		if !bytes.Equal(sum, hash) {
			t.Fatalf("Test vector %d : MAC does not match:\nFound:    %v\nExpected: %v", i, hex.EncodeToString(sum), hex.EncodeToString(hash))
		}

		sum, err = Sum(msg, key, v.tagsize)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to compute AES-CMAC checksum: %s", i, err)
		}
		if !bytes.Equal(sum, hash) {
			t.Fatalf("Test vector %d : MAC does not match:\nFound:    %v\nExpected: %v", i, hex.EncodeToString(sum), hex.EncodeToString(hash))
		}

		if !Verify(hash, msg, key, v.tagsize) {
			t.Fatalf("Test vector %d: verification of MAC failed", i)
		}

	}
}
