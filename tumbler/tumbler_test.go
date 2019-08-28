// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tumbler

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/tumblebit/puzzle"
	"github.com/decred/tumblebit/shuffle"
)

func TestPuzzlePromiseAndSolver(t *testing.T) {
	cfg := Config{
		EpochDuration:    EpochDuration,
		EpochRenewal:     EpochRenewal,
		PuzzleDifficulty: PuzzleDifficulty,
	}

	tb := NewTumbler(&cfg)

	if err := tb.NewEpoch(1234); err != nil {
		t.Fatalf("failed to setup an epoch: %v", err)
	}
	if err := tb.NewEpoch(1234); err == nil {
		t.Fatal("server allowed to setup the same epoch twice")
	}

	c1 := NewSession(tb, "")
	c1.state = StateEscrowComplete

	// Obtain current block height directly, bypassing SetupEscrow
	epoch, err := tb.getCurrentEpoch()
	if err != nil {
		t.Fatalf("failed to obtain current block height: %v", err)
	}
	c1.epoch = epoch

	pkey, blinded, inverse := testPuzzlePromise(t, c1)

	c2 := NewSession(tb, "")

	solution := testPuzzleSolving(t, c2, pkey, blinded, epoch)

	unblinded := puzzle.UnblindPuzzle(pkey, solution, inverse)

	if !bytes.Equal(c1.secrets[0], unblinded) {
		t.Logf("secret    %x\n", c1.secrets[0])
		t.Logf("blinded   %x\n", blinded)
		t.Logf("inverse   %x\n", inverse)
		t.Logf("solution  %x\n", solution)
		t.Logf("unblinded %x\n", unblinded)
		t.Fatal("puzzle protocol failed")
	}
}

func testPuzzlePromise(t *testing.T, s *Session) (*puzzle.PuzzlePubKey, []byte, []byte) {
	var err error
	var salt [32]byte

	rand.Read(salt[:])

	txh := make([][]byte, RealTransactionCount+FakeTransactionCount)

	realTxList := make([]int, RealTransactionCount)
	fakeTxList := make([]int, FakeTransactionCount)
	randomPads := make([][]byte, FakeTransactionCount)

	for i := range txh {
		if i < RealTransactionCount {
			txh[i] = chainhash.HashB([]byte{uint8(i)})
			realTxList[i] = i
		} else {
			randomPads[i-RealTransactionCount] = make([]byte, 32)
			rand.Read(randomPads[i-RealTransactionCount])
			txh[i] = puzzle.FakeTxFormat(randomPads[i-RealTransactionCount])
			fakeTxList[i-RealTransactionCount] = i
		}
	}

	// Shuffle transaction list
	sh := shuffle.Shuffle(rand.Reader, len(txh), func(i, j int) {
		txh[i], txh[j] = txh[j], txh[i]
	})

	// Update list indexes
	for i := range fakeTxList {
		fakeTxList[i] = sh.Get(fakeTxList[i])
	}
	for i := range realTxList {
		realTxList[i] = sh.Get(realTxList[i])
	}
	// Hash them up and serve.
	fakeSetHash, err := puzzle.HashIndexList(salt[:], fakeTxList)
	if err != nil {
		t.Fatalf("failed to generate index list hash: %v", err)
	}
	realSetHash, err := puzzle.HashIndexList(salt[:], realTxList)
	if err != nil {
		t.Fatalf("failed to generate index list hash: %v", err)
	}

	signatures, pubKey, err := signChallengeHashes(txh)
	if err != nil {
		t.Fatalf("failed to sign challenge hashes: %v", err)
	}

	promise, err := s.GetPuzzlePromises(context.TODO(), &SignatureChallenges{
		FakeSetHash:       fakeSetHash,
		RealSetHash:       realSetHash,
		TransactionHashes: txh,
		Signatures:        signatures,
		PublicKey:         pubKey,
	})
	if err != nil {
		t.Fatalf("failed to acquire puzzle promises: %v", err)
	}

	pkey, err := puzzle.ParsePubKey(promise.PuzzleKey)
	if err != nil {
		t.Fatal("failed to parse public key")
	}

	fakeTxIndexes, err := puzzle.EncodeIndexList(fakeTxList)
	if err != nil {
		t.Fatalf("failed to encode fake tx indexes: %v", err)
	}

	realTxIndexes, err := puzzle.EncodeIndexList(realTxList)
	if err != nil {
		t.Fatalf("failed to encode real tx indexes: %v", err)
	}

	secrets, err := s.ValidatePuzzles(context.TODO(), &TransactionDisclosure{
		FakeTxList: fakeTxIndexes,
		RealTxList: realTxIndexes,
		RandomPads: randomPads,
		Salt:       salt[:],
	})
	if err != nil {
		t.Fatalf("failed to acquire solutions to the fake set: %v", err)
	}
	if len(secrets.Secrets) != len(fakeTxList) {
		t.Fatal("obtained wrong amount of puzzle secrets")
	}

	for i, j := range fakeTxList {
		if !puzzle.ValidatePuzzle(&pkey, promise.Puzzles[j],
			secrets.Secrets[i]) {
			t.Fatal("obtained secrets didn't verify")
		}
		sig, err := puzzle.RevealSolution(promise.Promises[j],
			secrets.Secrets[i])
		if err != nil {
			t.Fatalf("failed to recover signature: %v", err)
		}
		if ok, err := secpVerify(sig, txh[j][:]); !ok {
			t.Fatalf("signature didn't verify: %v", err)
		}
	}

	realPuzzles := make([][]byte, len(realTxList))
	for i, idx := range realTxList {
		realPuzzles[i] = promise.Puzzles[idx]
	}
	if !puzzle.VerifyQuotients(&pkey, secrets.Quotients, realPuzzles) {
		t.Fatal("failed to verify quotients")
	}

	// Return blinding of a first puzzle
	blinding, _, inverse, err := puzzle.BlindPuzzle(&pkey, promise.Puzzles[0])
	if err != nil {
		t.Fatal("failed to blind the puzzle")
	}

	return &pkey, blinding, inverse
}

func testPuzzleSolving(t *testing.T, s *Session, pkey *puzzle.PuzzlePubKey,
	p []byte, epoch int32) []byte {
	var err error

	puzzles := make([][]byte, RealPreimageCount+FakePreimageCount)

	// Random blindings of the received puzzle
	realFactors := make([][]byte, RealPreimageCount)
	realInverses := make([][]byte, RealPreimageCount)
	realPzList := make([]int, RealPreimageCount)

	// A set of random fake factors to mix with puzzle blindings
	fakeFactors := make([][]byte, FakePreimageCount)
	fakePzList := make([]int, FakePreimageCount)

	// A cheap hack: BlindPuzzle will multiply a random factor and 1
	one := big.NewInt(1).Bytes()

	for i := range puzzles {
		if i < FakePreimageCount {
			puzzles[i], fakeFactors[i], _, err =
				puzzle.BlindPuzzle(pkey, one)
			if err != nil {
				t.Fatal(err)
			}
			fakePzList[i] = i
		} else {
			puzzles[i], realFactors[i-FakePreimageCount],
				realInverses[i-FakePreimageCount], err =
				puzzle.BlindPuzzle(pkey, p)
			if err != nil {
				t.Fatal(err)
			}
			realPzList[i-FakePreimageCount] = i
		}
	}

	// Shuffle puzzle list
	sh := shuffle.Shuffle(rand.Reader, len(puzzles), func(i, j int) {
		puzzles[i], puzzles[j] = puzzles[j], puzzles[i]
	})

	// Update list indexes
	for i := range fakePzList {
		fakePzList[i] = sh.Get(fakePzList[i])
	}
	for i := range realPzList {
		realPzList[i] = sh.Get(realPzList[i])
	}

	promise, err := s.GetSolutionPromises(context.TODO(), &SolutionChallenges{
		Epoch:   epoch,
		Puzzles: puzzles,
	})
	if err != nil {
		t.Fatal(err)
	}

	fakePzIndexes, err := puzzle.EncodeIndexList(fakePzList)
	if err != nil {
		t.Fatalf("failed to encode puzzle indexes: %v", err)
	}

	// Once solution promises are obtained, we can reveal idexes of puzzles
	// from the fake set and associated random values and exchange them for
	// keys to matching solutions.
	secrets, err := s.ValidateSolutions(context.TODO(), &PuzzleDisclosure{
		FakePuzzleList: fakePzIndexes,
		FakeFactors:    fakeFactors,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets.Secrets) != len(fakePzList) {
		t.Fatal("obtained wrong amount of solution secrets")
	}
	// Verify secret keys
	for i, idx := range fakePzList {
		if !bytes.Equal(chainhash.HashB(secrets.Secrets[i]),
			promise.KeyHashes[idx]) {
			t.Fatal("secret hash didn't verify")
		}
		solution, err := puzzle.RevealSolution(promise.Promises[idx],
			secrets.Secrets[i])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(solution, fakeFactors[i]) {
			t.Fatal("solution didn't verify")
		}
	}

	realPzIndexes, err := puzzle.EncodeIndexList(realPzList)
	if err != nil {
		t.Fatalf("failed to encode real puzzle indexes: %v", err)
	}
	s.realPuzzleList = realPzList

	// Reveal blinding factors for real puzzles.
	solutions, err := s.RevealSolution(context.TODO(), &PaymentOffer{
		Puzzle:         p,
		RealPuzzleList: realPzIndexes,
		RealFactors:    realFactors,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(solutions) != len(realPzList) {
		t.Fatal("obtained wrong amount of solution secrets")
	}
	// Verify secret keys
	puzzleSolutions := make([][]byte, len(realPzList))
	for i, idx := range realPzList {
		if !bytes.Equal(chainhash.HashB(solutions[i]),
			promise.KeyHashes[idx]) {
			t.Fatal("secret hash didn't verify")
		}
		solution, err := puzzle.RevealSolution(promise.Promises[idx],
			solutions[i])
		if err != nil {
			t.Fatal(err)
		}
		if !puzzle.ValidatePuzzle(pkey, puzzles[idx], solution) {
			t.Fatal("solution didn't verify")
		}
		puzzleSolutions[i] = puzzle.UnblindPuzzle(pkey, solution,
			realInverses[i])
	}
	for i := 1; i < len(puzzleSolutions); i++ {
		if !bytes.Equal(puzzleSolutions[i], puzzleSolutions[i-1]) {
			t.Fatal("puzzle solutions aren't unique")
		}
	}

	return puzzleSolutions[0]
}

var ecpriv chainec.PrivateKey
var ecpub chainec.PublicKey

func init() {
	priv, _, _, err := chainec.Secp256k1.GenerateKey(rand.Reader)
	if err != nil {
		panic("failed to generate private key")
	}
	ecpriv, ecpub = chainec.Secp256k1.PrivKeyFromBytes(priv)
}

func secpSign(hash []byte) ([]byte, error) {
	r, s, err := chainec.Secp256k1.Sign(ecpriv, hash)
	if err != nil {
		return nil, err
	}
	sig := chainec.Secp256k1.NewSignature(r, s)
	return sig.Serialize(), nil
}

func secpVerify(sigBytes []byte, hash []byte) (bool, error) {
	sig, err := chainec.Secp256k1.ParseSignature(sigBytes)
	if err != nil {
		return false, err
	}
	if !chainec.Secp256k1.Verify(ecpub, hash, sig.GetR(), sig.GetS()) {
		return false, errors.New("failed to verify the signature")
	}
	return true, nil
}

func signChallengeHashes(hashes [][]byte) ([][]byte, []byte, error) {
	var err error
	signatures := make([][]byte, len(hashes))
	for i, hash := range hashes {
		signatures[i], err = secpSign(hash)
		if err != nil {
			return nil, nil, err
		}
	}
	return signatures, ecpub.Serialize(), nil
}
