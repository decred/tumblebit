// Copyright 2009 The Go Authors. All rights reserved.
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// The puzzle package implements cryptographic primitives to generate,
// conceal (blind) and solve puzzles required by the TumbleBit protocol.
package puzzle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/crypto/ripemd160"
	"golang.org/x/crypto/blake2s"
)

func NewPuzzlePromise(pk *PuzzleKey, sig []byte) ([]byte, []byte, []byte, error) {
	// Generate a random secret value in the interval [0, N)
	secret, err := rand.Int(rand.Reader, pk.rsakey.N)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to generate a puzzle secret: %v", err)
	}

	// Create puzzle & promise
	puzzle := createPuzzle(pk.PublicKey(), secret)
	promise, err := createPromise(sig, secret.Bytes())
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to create puzzle promise: %v", err)
	}
	return puzzle, promise, secret.Bytes(), nil
}

// Puzzle z is computed as secret^e mod N.
func createPuzzle(pk *PuzzlePubKey, secret *big.Int) []byte {
	bigE := big.NewInt(int64(pk.E))
	z := new(big.Int).Exp(secret, bigE, pk.N)
	return z.Bytes()
}

// createPromise encrypts arbitrary data with BLAKE2x XOF in OTP mode keyed
// with secret.
func createPromise(data []byte, secret []byte) ([]byte, error) {
	return cryptWithXOF(data, secret)
}

// ValidatePuzzle makes sure that secret encrypts to the same value as the
// puzzle with the provided public key pk.
func ValidatePuzzle(pk *PuzzlePubKey, puzzle, secret []byte) bool {
	bigSecret := new(big.Int).SetBytes(secret)
	if bigSecret.Cmp(pk.N) >= 0 {
		return false
	}
	check := createPuzzle(pk, bigSecret)
	return subtle.ConstantTimeCompare(check, puzzle) == 1
}

// ValidateBlindedPuzzle makes sure that the encrypted secret is a correct
// blinding factor for the puzzle with the provided public key pk.
// Essentially this checks that blinding = puzzle * secret^e.
func ValidateBlindedPuzzle(pk *PuzzlePubKey, blinding, puzzle []byte, secret []byte) bool {
	bigSecret := new(big.Int).SetBytes(secret)
	if bigSecret.Cmp(pk.N) >= 0 {
		return false
	}
	check := UnblindPuzzle(pk, puzzle, createPuzzle(pk, bigSecret))
	return subtle.ConstantTimeCompare(check, blinding) == 1
}

func RevealSolution(promise []byte, secret []byte) ([]byte, error) {
	return cryptWithXOF(promise, secret)
}

// cryptWithXOF performs OTP encryption of input data using secret as a key.
func cryptWithXOF(input []byte, secret []byte) ([]byte, error) {
	if len(input) > 65535 {
		return nil, errors.New("input too long")
	}
	klen := blake2s.Size
	if len(secret) < blake2s.Size {
		klen = len(secret)
	}
	xof, err := blake2s.NewXOF(uint16(len(input)), secret[:klen])
	if err != nil {
		return nil, err
	}
	// Feed the rest of the secret into the hash
	xof.Write(secret[klen:])
	// Read keystream
	keystream := make([]byte, len(input))
	xof.Read(keystream)
	// XOR input with keystream
	output := make([]byte, len(input))
	for i := range output {
		output[i] = keystream[i] ^ input[i]
	}
	return output, nil
}

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// newBlindingFactor allocates and returns a non-zero random number less
// than than modulus and its multiplicative inverse in Z/nZ.
func newBlindingFactor(priv *rsa.PublicKey) (*big.Int, *big.Int, error) {
	var r, ir *big.Int
	var err error
	for {
		r, err = rand.Int(rand.Reader, priv.N)
		if err != nil {
			return nil, nil, err
		}
		if r.Cmp(bigZero) == 0 {
			continue
		}
		var ok bool
		ir, ok = modInverse(r, priv.N)
		if ok {
			break
		}
	}
	return r, ir, nil
}

// BlindPuzzle generates a random factor and returns a product of the puzzle p
// and the factor as well as the multiplicative inverse of the factor suitable
// for UnblindPuzzle.
func BlindPuzzle(pk *PuzzlePubKey, p []byte) ([]byte, []byte, []byte, error) {
	r, ir, err := newBlindingFactor((*rsa.PublicKey)(pk))
	if err != nil {
		return nil, nil, nil, err
	}
	bigE := big.NewInt(int64(pk.E))
	rpowe := new(big.Int).Exp(r, bigE, pk.N)
	z := new(big.Int).SetBytes(p)
	z.Mul(z, rpowe)
	z.Mod(z, pk.N)
	return z.Bytes(), r.Bytes(), ir.Bytes(), nil
}

// UnblindPuzzle recovers the original value of the puzzle by muliplying it
// with an inverse obtained from BlindedPuzzle.
func UnblindPuzzle(pk *PuzzlePubKey, p []byte, r []byte) []byte {
	bigP := new(big.Int).SetBytes(p)
	bigR := new(big.Int).SetBytes(r)
	bigP.Mul(bigP, bigR)
	bigP.Mod(bigP, pk.N)
	return bigP.Bytes()
}

// SolvePuzzle decrypts the puzzle p using the private key pk.
func SolvePuzzle(pk *PuzzleKey, p []byte) ([]byte, error) {
	m, err := decryptPuzzle(pk, new(big.Int).SetBytes(p))
	if err != nil {
		return nil, err
	}

	// In order to defend against errors in the CRT computation, m^e is
	// calculated, which should match the original ciphertext.
	check := createPuzzle(pk.PublicKey(), m)
	if subtle.ConstantTimeCompare(check, p) != 1 {
		return nil, errors.New("error in the CRT computation")
	}

	return m.Bytes(), nil
}

// decryptPuzzle performs an RSA decryption, resulting in a plaintext integer.
func decryptPuzzle(pk *PuzzleKey, c *big.Int) (*big.Int, error) {
	var m *big.Int

	priv := pk.rsakey

	if c.Cmp(priv.N) > 0 {
		return nil, errors.New("value too large")
	}

	bigE := big.NewInt(int64(priv.E))
	rpowe := new(big.Int).Exp(pk.factor, bigE, priv.N) // N != 0
	cCopy := new(big.Int).Set(c)
	cCopy.Mul(cCopy, rpowe)
	cCopy.Mod(cCopy, priv.N)
	c = cCopy

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	// Unblind.
	m.Mul(m, pk.inverse)
	m.Mod(m, priv.N)

	return m, nil
}

// NewSolutionPromise recovers a solution to the puzzle p and generates a
// promise that puzzle p opens up to this solution.
func NewSolutionPromise(pk *PuzzleKey, p []byte) ([]byte, []byte, []byte, error) {
	secret := make([]byte, ripemd160.Size)
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, nil, nil, err
	}

	solution, err := SolvePuzzle(pk, p)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to solve the puzzle: %v", err)
	}

	promise, err := createPromise(solution, secret)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("failed to create solution promise: %v", err)
	}
	return solution, promise, secret, nil
}

// Quotients returns an slice of quotients, where i'th value is calculated
// as secret[i] divided by secret[i-1], effectively chaining them together.
func Quotients(pk *PuzzlePubKey, secrets [][]byte) ([][]byte, error) {
	quotients := make([][]byte, len(secrets))
	quotients[0] = bigOne.Bytes()
	for i := 1; i < len(secrets); i++ {
		a := new(big.Int).SetBytes(secrets[i-1])
		b := new(big.Int).SetBytes(secrets[i])
		ai, ok := modInverse(a, pk.N)
		if !ok {
			return nil, errors.New("malformed secret")
		}
		// q = b/a mod N = b*a^-1 mod N
		q := new(big.Int)
		q.Mul(b, ai)
		q.Mod(q, pk.N)
		quotients[i] = q.Bytes()
	}
	return quotients, nil
}

// VerifyQuotientsWithSecrets verifies that quotients are constructed correctly
// by making sure that i'th secret can be recovered as a product of preceding
// quotient values.
func VerifyQuotientsWithSecrets(pk *PuzzlePubKey, qs [][]byte, secrets [][]byte) bool {
	// Verify that i'th secret can be recovered as a product:
	// s_i = s_0 * qs[0] * qs[1] * ... * qs[i]
	prod := new(big.Int).SetBytes(secrets[0])
	for i := range qs {
		q := new(big.Int).SetBytes(qs[i])
		prod.Mul(prod, q)
		prod.Mod(prod, pk.N)
		if subtle.ConstantTimeCompare(secrets[i], prod.Bytes()) != 1 {
			return false
		}
	}
	return true
}

// VerifyQuotients verifies that quotients are constructed correctly by making
// sure that i'th puzzle can be recovered as a product of a preceding puzzle
// and i'th quotient raised to the power of e. In other words, each quotient
// becomes a blinding factor linking puzzles together.
func VerifyQuotients(pk *PuzzlePubKey, qs [][]byte, puzzles [][]byte) bool {
	// Verify that i'th puzzle can be recovered as a product:
	// z_i = z_(i-1) * q_i
	bigE := big.NewInt(int64(pk.E))
	for i := 1; i < len(qs); i++ {
		z := new(big.Int).SetBytes(puzzles[i-1])
		q := new(big.Int).SetBytes(qs[i])
		q.Exp(q, bigE, pk.N)
		z.Mul(z, q)
		z.Mod(z, pk.N)
		if subtle.ConstantTimeCompare(puzzles[i], z.Bytes()) != 1 {
			return false
		}
	}
	return true
}

// modInverse returns the inverse of a in the multiplicative group of prime
// order n. It requires that a be a member of the group (i.e. less than n).
func modInverse(a, n *big.Int) (*big.Int, bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		// In this case, a and n aren't coprime and we cannot calculate
		// the inverse. This happens because the values of n are nearly
		// prime (being the product of two primes) rather than truly
		// prime.
		return nil, false
	}

	if x.Cmp(bigOne) < 0 {
		// 0 is not the multiplicative inverse of any element so, if x
		// < 1, then x is negative.
		x.Add(x, n)
	}

	return x, true
}
