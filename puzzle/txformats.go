// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package puzzle

import (
	"github.com/decred/dcrd/chaincfg/chainhash"
)

// FakeTxFormat generates a hash value for a transaction dummy with a known
// structure so that it can be verified given the knowledge of a random pad.
func FakeTxFormat(randomPad []byte) []byte {
	fakeTx := []byte{'f', 'a', 'k', 'e', 'f', 'a', 'k', 'e', 'f', 'a', 'k', 'e'}
	fakeTx = append(fakeTx, randomPad...)
	return chainhash.HashB(fakeTx)
}
