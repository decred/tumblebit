// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package puzzle_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/tumblebit/puzzle"
)

const PuzzlesAmount = 256

func TestBasicPuzzlePromise(t *testing.T) {
	var err error

	r := rand.New(rand.NewSource(1))

	txh := make([]*chainhash.Hash, PuzzlesAmount)
	for i := 0; i < PuzzlesAmount; i++ {
		var hash [chainhash.HashSize]byte
		r.Read(hash[:])
		txh[i], err = chainhash.NewHash(hash[:])
		if err != nil {
			t.Fatal(err)
		}
	}

	priv, err := puzzle.GeneratePuzzleKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pk := priv.PublicKey()

	puzzles := make([][]byte, len(txh))
	promises := make([][]byte, len(txh))
	secrets := make([][]byte, len(txh))
	for i := range txh {
		puzzles[i], promises[i], secrets[i], err =
			puzzle.NewPuzzlePromise(priv, txh[i][:])
		if err != nil {
			t.Fatal(err)
		}
	}

	solutions := make([][]byte, len(puzzles))

	for i := range puzzles {
		b, _, ir, err := puzzle.BlindPuzzle(pk, puzzles[i])
		if err != nil {
			tracePuzzle(t, txh[i][:], puzzles[i], promises[i])
			t.Fatal(err)
		}

		x, err := puzzle.SolvePuzzle(priv, b)
		if err != nil {
			tracePuzzle(t, txh[i][:], puzzles[i], promises[i], b, x)
			t.Fatal(err)
		}

		u := puzzle.UnblindPuzzle(pk, x, ir)
		if !bytes.Equal(u, secrets[i]) {
			tracePuzzle(t, txh[i][:], puzzles[i], promises[i], b, x, u)
			t.Fatal("failed to solve blinded puzzle")
		}

		s, err := puzzle.RevealSolution(promises[i], u)
		if err != nil {
			tracePuzzle(t, txh[i][:], puzzles[i], promises[i], b, x, u, s)
			t.Fatal(err)
		}

		if !bytes.Equal(txh[i][:], s) {
			tracePuzzle(t, txh[i][:], puzzles[i], promises[i], b, x, u, s)
			t.Fatal("solution didn't verify")
		}

		solutions[i] = u
	}

	quotients, err := puzzle.Quotients(pk, solutions)
	if err != nil {
		t.Fatal(err)
	}
	if !puzzle.VerifyQuotientsWithSecrets(pk, quotients, solutions) {
		t.Fatal("failed to verify quotients")
	}
}

func tracePuzzle(t *testing.T, blocks ...[]byte) {
	var legend = []string{
		"secret   ",
		"puzzle   ",
		"promise  ",
		"blinded  ",
		"solved   ",
		"unblind  ",
		"solution ",
	}
	for i, block := range blocks {
		t.Logf("%s %#x\n", legend[i], block)
	}
}

func BenchmarkGenPuzzles2048(b *testing.B) {
	priv, err := puzzle.GeneratePuzzleKey(2048)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		puzzle.NewPuzzlePromise(priv, []byte{0})
	}
}

func BenchmarkGenPuzzles3072(b *testing.B) {
	priv, err := puzzle.GeneratePuzzleKey(3072)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		puzzle.NewPuzzlePromise(priv, []byte{0})
	}
}

func BenchmarkGenPuzzles4096(b *testing.B) {
	priv, err := puzzle.GeneratePuzzleKey(4096)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		puzzle.NewPuzzlePromise(priv, []byte{0})
	}
}

func BenchmarkRevealSolution(b *testing.B) {
	priv, err := puzzle.GeneratePuzzleKey(2048)
	if err != nil {
		b.Fatal(err)
	}
	puzzles := make([][]byte, 256)
	promises := make([][]byte, 256)
	for i := 0; i < 256; i++ {
		puzzles[i], promises[i], _, err =
			puzzle.NewPuzzlePromise(priv, []byte{byte(i)})
		if err != nil {
			b.Fatal(err)
		}
		// skip blinding and go straight to solving
		puzzles[i], err = puzzle.SolvePuzzle(priv, puzzles[i])
		if err != nil {
			b.Fatal(err)
		}
	}
	// at this point p contains puzzle solutions and promises
	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		for i := 0; i < 256; i++ {
			puzzle.RevealSolution(promises[i], puzzles[i])
		}
	}
}
