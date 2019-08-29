// Copyright 2009 The Go Authors. All rights reserved.
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shuffle

import (
	"encoding/binary"
	"io"
)

type ShuffleMap struct {
	perm []int // permutation map
}

// Shuffle pseudo-randomizes the order of elements.
// n is the number of elements. Shuffle panics if n is negative or too large.
// swap swaps the elements with indexes i and j.
func Shuffle(random io.Reader, n int, swap func(i, j int)) *ShuffleMap {
	if n < 0 || n > (1<<31-1-1) {
		panic("invalid argument to Shuffle")
	}

	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	perm := make([]int, n)

	// Fisher-Yates shuffle: https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
	for i := n - 1; i > 0; i-- {
		j := int(uniformRandom31(random, int32(i+1)))
		swap(i, j)
		idx[i], idx[j] = idx[j], idx[i]
		perm[idx[i]] = i
	}
	return &ShuffleMap{perm}
}

func (s *ShuffleMap) Get(index int) int {
	return s.perm[index]
}

func uniformRandom31(random io.Reader, n int32) int32 {
	var v uint32
	binary.Read(random, binary.LittleEndian, &v)
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < uint32(n) {
		thresh := uint32(-n) % uint32(n)
		for low < thresh {
			binary.Read(random, binary.LittleEndian, &v)
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return int32(prod >> 32)
}
