// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package puzzle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
)

type PuzzleKey struct {
	rsakey  *rsa.PrivateKey
	factor  *big.Int
	inverse *big.Int
}

type PuzzlePubKey rsa.PublicKey

func GeneratePuzzleKey(difficulty int) (*PuzzleKey, error) {
	var err error

	pk := new(PuzzleKey)
	// We determine the safe number of primes for a specified difficulty
	// according to the following paper by M. Jason Hinek:
	// http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
	nprimes := 2
	if difficulty >= 8192 {
		nprimes = 5
	} else if difficulty >= 4096 {
		nprimes = 4
	} else if difficulty >= 1024 {
		nprimes = 3
	}
	pk.rsakey, err = rsa.GenerateMultiPrimeKey(rand.Reader, nprimes, difficulty)
	if err != nil {
		return nil, err
	}
	pk.factor, pk.inverse, err = newBlindingFactor(&pk.rsakey.PublicKey)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func (pk *PuzzleKey) PublicKey() *PuzzlePubKey {
	return &PuzzlePubKey{
		E: pk.rsakey.E,
		N: pk.rsakey.N,
	}
}

func MarshalPubKey(pk *PuzzleKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&pk.rsakey.PublicKey)
}

func ParsePubKey(pub []byte) (PuzzlePubKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return PuzzlePubKey{}, err
	}
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		return PuzzlePubKey{
			E: pubKey.E,
			N: pubKey.N,
		}, nil
	default:
		return PuzzlePubKey{}, errors.New("unknown public key type")
	}
}
