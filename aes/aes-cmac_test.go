// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package aes

import "testing"

func TestNew(t *testing.T) {
	var keys = [3]int{16, 24, 32}
	for _, k := range keys {
		_, err := New(make([]byte, k))
		if err != nil {
			t.Fatalf("Key Size: %d, Failed to create AES-CMAC instance: %s", k, err)
		}
	}

	_, err := New(make([]byte, 12))
	if err == nil {
		t.Fatalf("AES-CMAC allowed invalid key size : %d", 12)
	}
}

func TestSum(t *testing.T) {
	_, err := Sum(nil, make([]byte, 12), 16)
	if err == nil {
		t.Fatalf("AES-CMAC allowed invalid key size : %d", 12)
	}
}

func TestVerify(t *testing.T) {
	sum, err := Sum(nil, make([]byte, 16), 16)
	if err != nil {
		t.Fatalf("Failed to compute AES-CMAC checksum: %s", err)
	}

	if Verify(sum, sum, make([]byte, 12), 16) {
		t.Fatalf("AES-CMAC allowed invalid key size : %d", 12)
	}
}
