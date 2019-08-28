// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tumbler

const (
	// EpochDuration defines the duration of a single epoch, i.e.
	// the period within which Escrow, Payment and Chash-Out phases of
	// the TumbleBit protocol take place. Incidentally, it also specifies
	// for how long tumbler's funds are escrowed and when it can post a
	// redeeming transaction to reclaim those funds.
	EpochDuration = 10

	// EpochRenewal defines an interval between two consecutive epochs
	// expressed in a number of blocks.
	EpochRenewal = EpochDuration / 2

	// PuzzleDifficulty determines Tumbler's RSA group size.
	// Perhaps should be made more generic and expressed in terms of O(2^n)
	// complexity, where n is 128, 192 or 256 "bits of security".
	PuzzleDifficulty = 2048

	// RealTransactionCount specifies a number of real transactions that
	// client should be supplying. The chosen values constitute to approx.
	// ~80 bits of security, i.e. one in a 2^(42+42) chance of cheating
	// for the Tumbler during puzzle-promise protocol.
	RealTransactionCount = 42

	// FakeTransactionCount specifies a number of fake transactions to
	// mix in to the provided list of transaction hashes. Shouldn't be
	// less than the amount of RealTransactionCount.
	FakeTransactionCount = RealTransactionCount

	// RealPreimageCount is the number of preimages payer will put in their
	// P2SH transaction.  NOTE: When changing this value, the redeem script
	// size estimator (wallet.redeemEscrowSigScriptSize) needs to be updated
	// as well.
	RealPreimageCount = 15

	// FakePreimageCount is the number of fake preimages used to verify
	// Tumbler's fairness during puzzle-solving protocol.
	FakePreimageCount = 285
)
