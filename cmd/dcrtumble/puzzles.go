// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/tumblebit/puzzle"
	"github.com/decred/tumblebit/shuffle"
)

type puzzleSolverChallenge struct {
	puzzles        [][]byte
	fakePuzzleList []byte
	realPuzzleList []byte
	fakeFactors    [][]byte
	realFactors    [][]byte
	realInverses   [][]byte
}

// createPuzzleSolverChallenge generates a shuffled set of puzzles
// consisting of puzzle blinded with distinct random factors and fake
// factors indistinguishable from a blinded puzzle.
func createPuzzleSolverChallenge(p []byte, puzzleKey []byte) (*puzzleSolverChallenge, error) {
	var err error

	pkey, err := puzzle.ParsePubKey(puzzleKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode puzzle key: %v", err)
	}

	puzzles := make([][]byte, RealPreimageCount+FakePreimageCount)

	// Random blindings of the received puzzle
	realFactors := make([][]byte, RealPreimageCount)
	realInverses := make([][]byte, RealPreimageCount)
	realPuzzleList := make([]int, RealPreimageCount)

	// A set of random fake factors to mix with puzzle blindings
	fakeFactors := make([][]byte, FakePreimageCount)
	fakePuzzleList := make([]int, FakePreimageCount)

	// A cheap hack: BlindPuzzle will multiply a random factor and 1
	one := big.NewInt(1).Bytes()

	for i := range puzzles {
		if i < FakePreimageCount {
			puzzles[i], fakeFactors[i], _, err =
				puzzle.BlindPuzzle(&pkey, one)
			if err != nil {
				return nil, err
			}
			fakePuzzleList[i] = i
		} else {
			puzzles[i], realFactors[i-FakePreimageCount],
				realInverses[i-FakePreimageCount], err =
				puzzle.BlindPuzzle(&pkey, p)
			if err != nil {
				return nil, fmt.Errorf("failed to : %v", err)
			}
			realPuzzleList[i-FakePreimageCount] = i
		}
	}

	// Shuffle puzzle list
	s := shuffle.Shuffle(rand.Reader, len(puzzles), func(i, j int) {
		puzzles[i], puzzles[j] = puzzles[j], puzzles[i]
	})

	// Update list indexes
	for i := range fakePuzzleList {
		fakePuzzleList[i] = s.Get(fakePuzzleList[i])
	}
	for i := range realPuzzleList {
		realPuzzleList[i] = s.Get(realPuzzleList[i])
	}

	serFakePuzzleList, err := puzzle.EncodeIndexList(fakePuzzleList)
	if err != nil {
		return nil, fmt.Errorf("failed to encode fake puzzle indexes: "+
			"%v", err)
	}

	serRealPuzzleList, err := puzzle.EncodeIndexList(realPuzzleList)
	if err != nil {
		return nil, fmt.Errorf("failed to encode real puzzle indexes: "+
			"%v", err)
	}

	return &puzzleSolverChallenge{
		puzzles:        puzzles,
		fakePuzzleList: serFakePuzzleList,
		realPuzzleList: serRealPuzzleList,
		fakeFactors:    fakeFactors,
		realFactors:    realFactors,
		realInverses:   realInverses,
	}, nil
}

type puzzleSolverResponse struct {
	promises  [][]byte
	keyHashes [][]byte
	secrets   [][]byte
}

// validatePuzzleSolverResponse verifies secret keys provided by the tumbler
// and makes sure they can be used to unlock fake puzzles.
func validatePuzzleSolverResponse(c *puzzleSolverChallenge, r *puzzleSolverResponse) error {
	fakePuzzleList, err := puzzle.DecodeIndexList(c.fakePuzzleList)
	if err != nil {
		return errors.New("failed to decode an index list")
	}

	for i, idx := range fakePuzzleList {
		if !bytes.Equal(chainhash.HashB(r.secrets[i]), r.keyHashes[idx]) {
			return errors.New("secret hash didn't verify")
		}
		solution, err := puzzle.RevealSolution(r.promises[idx],
			r.secrets[i])
		if err != nil {
			return fmt.Errorf("puzzle didn't unlock: %v", err)
		}
		if !bytes.Equal(solution, c.fakeFactors[i]) {
			return fmt.Errorf("solution didn't verify")
		}
	}

	return nil
}

func createPreimageChallanges(c *puzzleSolverChallenge, r *puzzleSolverResponse) ([][]byte, error) {
	realPuzzleList, err := puzzle.DecodeIndexList(c.realPuzzleList)
	if err != nil {
		return nil, errors.New("failed to decode an index list")
	}

	keyHashes := make([][]byte, 0, len(realPuzzleList))
	for _, idx := range realPuzzleList {
		keyHashes = append(keyHashes, r.keyHashes[idx])
	}
	return keyHashes, nil
}

type puzzlePromiseChallenge struct {
	txHashes    [][]byte
	salt        []byte
	randomPads  [][]byte
	realTxList  []byte
	fakeTxList  []byte
	realSetHash []byte
	fakeSetHash []byte
}

func createPuzzlePromiseChallenge(realTxHashes [][]byte) (*puzzlePromiseChallenge, error) {
	txh := make([][]byte, RealTransactionCount+FakeTransactionCount)

	fakeTxList := make([]int, FakeTransactionCount)
	realTxList := make([]int, RealTransactionCount)
	randomPads := make([][]byte, FakeTransactionCount)

	for i := range txh {
		if i < FakeTransactionCount {
			randomPads[i] = make([]byte, 32)
			rand.Read(randomPads[i])
			txh[i] = puzzle.FakeTxFormat(randomPads[i])
			fakeTxList[i] = i
		} else {
			txh[i] = realTxHashes[i-FakeTransactionCount]
			realTxList[i-FakeTransactionCount] = i
		}
	}

	// Shuffle transaction list
	s := shuffle.Shuffle(rand.Reader, len(txh), func(i, j int) {
		txh[i], txh[j] = txh[j], txh[i]
	})

	// Update list indexes
	for i := range fakeTxList {
		fakeTxList[i] = s.Get(fakeTxList[i])
	}
	for i := range realTxList {
		realTxList[i] = s.Get(realTxList[i])
	}

	serFakeTxList, err := puzzle.EncodeIndexList(fakeTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to encode fake tx indexes: %v",
			err)
	}

	serRealTxList, err := puzzle.EncodeIndexList(realTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to encode real tx indexes: %v",
			err)
	}

	salt := make([]byte, 32)
	if _, err = rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Hash them up and serve.
	fakeSetHash, err := puzzle.HashIndexList(salt, fakeTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to generate index list hash: %v",
			err)
	}
	realSetHash, err := puzzle.HashIndexList(salt, realTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to generate index list hash: %v",
			err)
	}

	return &puzzlePromiseChallenge{
		txHashes:    txh,
		salt:        salt,
		randomPads:  randomPads,
		fakeTxList:  serFakeTxList,
		realTxList:  serRealTxList,
		fakeSetHash: fakeSetHash,
		realSetHash: realSetHash,
	}, nil
}

type puzzlePromiseResponse struct {
	puzzles   [][]byte
	promises  [][]byte
	quotients [][]byte
	secrets   [][]byte
	puzzleKey []byte
	publicKey []byte
}

func validatePuzzlePromiseResponse(c *puzzlePromiseChallenge, r *puzzlePromiseResponse) error {
	pkey, err := puzzle.ParsePubKey(r.puzzleKey)
	if err != nil {
		return fmt.Errorf("failed to decode puzzle key: %v", err)
	}

	fakeTxList, err := puzzle.DecodeIndexList(c.fakeTxList)
	if err != nil {
		return fmt.Errorf("failed to decode fake tx index list: %v", err)
	}
	realTxList, err := puzzle.DecodeIndexList(c.realTxList)
	if err != nil {
		return fmt.Errorf("failed to decode real tx index list: %v", err)
	}

	for i, j := range fakeTxList {
		if !puzzle.ValidatePuzzle(&pkey, r.puzzles[j], r.secrets[i]) {
			return errors.New("obtained secrets didn't verify")
		}
		sig, err := puzzle.RevealSolution(r.promises[j], r.secrets[i])
		if err != nil {
			return fmt.Errorf("failed to recover signature: %v", err)
		}
		err = verifySignature(sig, c.txHashes[j][:], r.publicKey)
		if err != nil {
			return fmt.Errorf("signature didn't verify: %v", err)
		}
	}

	realPuzzles := make([][]byte, len(realTxList))
	for i, idx := range realTxList {
		realPuzzles[i] = r.puzzles[idx]
	}
	if !puzzle.VerifyQuotients(&pkey, r.quotients, realPuzzles) {
		return errors.New("failed to verify quotients")
	}

	return nil
}

func createClientPuzzle(c *puzzlePromiseChallenge, r *puzzlePromiseResponse) (int, []byte, []byte, error) {
	realTxList, err := puzzle.DecodeIndexList(c.realTxList)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to decode tx index"+
			" list: %v", err)
	}

	// Pick puzzle at random to avoid any dependencies on the known index
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return 0, nil, nil, fmt.Errorf("failed to generate seed:"+
			" %v", err)
	}
	seed := int64(binary.LittleEndian.Uint64(buf))
	rnd := mrand.New(mrand.NewSource(seed))

	var which int
out:
	for {
		which := int(rnd.Int31n(int32(len(r.puzzles))))
		// See if which is one of real transactions
		for _, valid := range realTxList {
			if which == valid {
				break out
			}
		}
	}

	pkey, err := puzzle.ParsePubKey(r.puzzleKey)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to decode puzzle "+
			"key: %v", err)
	}

	puzzle, _, factor, err := puzzle.BlindPuzzle(&pkey, r.puzzles[which])
	if err != nil {
		return 0, nil, nil, err
	}
	return which, puzzle, factor, nil
}

func verifySignature(sigBytes []byte, hash []byte, publicKey []byte) error {
	pubkey, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return err
	}
	sig, err := ecdsa.ParseDERSignature(sigBytes)
	if err != nil {
		return err
	}
	if !sig.Verify(hash, pubkey) {
		return errors.New("failed to verify the signature")
	}
	return nil
}
