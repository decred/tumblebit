// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/tumblebit/contract"
	"github.com/decred/tumblebit/wallet"
)

type PaymentPuzzle struct {
	Contract *contract.Contract
	Amount   int64
	Epoch    int32
	Puzzle   []byte
	Key      []byte
	Factor   []byte
	Origin   []byte
}

type PuzzleSolution struct {
	Contract *contract.Contract
	Solution []byte
}

func (tb *Tumbler) NewEscrow(ctx context.Context, w *wallet.Wallet) (*PaymentPuzzle, error) {
	// XXX
	var amount int64 = dcrutil.AtomsPerCoin

	recvAddr, recvPubKey, err := w.GetExtAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain an address for escrow: %v", err)
	}

	escrow, err := tb.SetupEscrow(ctx, &EscrowRequest{
		Address:   recvAddr,
		PublicKey: recvPubKey,
		Amount:    amount,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to establish an escrow: %v", err)
	}

	con, err := contract.New(tb.chainParams, amount,
		escrow.Epoch+EpochDuration)
	if err != nil {
		return nil, fmt.Errorf("Failed to setup an escrow contract: %v", err)
	}

	err = con.SetAddress(contract.ReceiverAddress, recvAddr, recvPubKey)
	if err != nil {
		return nil, fmt.Errorf("Bad receiver address: %v", err)
	}

	err = con.SetAddress(contract.SenderAddress, escrow.Address,
		escrow.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Bad sender address: %v", err)
	}

	con.EscrowBytes = escrow.EscrowTransaction
	con.EscrowScript = escrow.EscrowScript

	if err = w.CreateRedeem(ctx, con); err != nil {
		return nil, fmt.Errorf("Failed to create redeeming tx: %v", err)
	}

	txHashes := make([][]byte, RealTransactionCount)
	for i := range txHashes {
		if txHashes[i], err = redeemTxHash(con); err != nil {
			return nil, fmt.Errorf("Failed to hash redeeming tx: %v", err)
		}
	}

	challenge, err := createPuzzlePromiseChallenge(txHashes)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a puzzle-promise "+
			"challenge: %v", err)
	}

	promise, err := tb.GetPuzzlePromises(ctx, &SignatureChallenges{
		Cookie:            escrow.Cookie,
		FakeSetHash:       challenge.fakeSetHash,
		RealSetHash:       challenge.realSetHash,
		TransactionHashes: challenge.txHashes,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain a cash-out promise: %v",
			err)
	}

	if len(promise.Puzzles) != len(challenge.txHashes) {
		return nil, errors.New("Received an incomplete set of puzzles")
	}
	if len(promise.Promises) != len(challenge.txHashes) {
		return nil, errors.New("Received an incomplete set of puzzle" +
			" promises")
	}

	secrets, err := tb.FinalizeEscrow(ctx, &TransactionDisclosure{
		Cookie:     escrow.Cookie,
		FakeTxList: challenge.fakeTxList,
		RealTxList: challenge.realTxList,
		RandomPads: challenge.randomPads,
		Salt:       challenge.salt,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to finalize an escrow: %v", err)
	}

	response := &puzzlePromiseResponse{
		puzzles:   promise.Puzzles,
		promises:  promise.Promises,
		quotients: secrets.Quotients,
		secrets:   secrets.Secrets,
		puzzleKey: promise.PuzzleKey,
		publicKey: promise.PublicKey,
	}

	if err = validatePuzzlePromiseResponse(challenge, response); err != nil {
		return nil, fmt.Errorf("Failed to validate puzzle-promise "+
			"challenge response: %v", err)
	}

	// XXX: Make sure secrets.EscrowHash gets at least 2 confirmations

	which, puzzle, factor, err := createClientPuzzle(challenge, response)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a puzzle for a "+
			"client: %v", err)
	}

	return &PaymentPuzzle{
		Contract: con,
		Amount:   amount,
		Epoch:    escrow.Epoch,
		Puzzle:   puzzle,
		Key:      promise.PuzzleKey,
		Factor:   factor,
		Origin:   promise.Puzzles[which],
	}, nil
}

func (tb *Tumbler) MakePayment(ctx context.Context, w *wallet.Wallet, pp *PaymentPuzzle) (*PuzzleSolution, error) {
	sendAddr, sendPubKey, err := w.GetExtAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain an address for an "+
			"escrow: %v", err)
	}

	// Create puzzles to obtain the purchase promises
	challenge, err := createPuzzleSolverChallenge(pp.Puzzle, pp.Key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a puzzle-solver "+
			"challenge: %v", err)
	}

	promise, err := tb.GetSolutionPromises(ctx, &SolutionChallenges{
		Address: sendAddr,
		Epoch:   pp.Epoch,
		Puzzles: challenge.puzzles,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain purchase promises: %v",
			err)
	}

	if len(promise.Promises) != len(challenge.puzzles) {
		return nil, errors.New("Received an incomplete set of promises")
	}
	if len(promise.KeyHashes) != len(challenge.puzzles) {
		return nil, errors.New("Received an incomplete set of key " +
			"hashes")
	}

	secrets, err := tb.ValidateSolutions(ctx, &PuzzleDisclosure{
		Cookie:         promise.Cookie,
		FakePuzzleList: challenge.fakePuzzleList,
		RandomFactors:  challenge.fakeFactors,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain solution secrets: %v",
			err)
	}

	if len(secrets.Secrets) != FakePreimageCount {
		return nil, errors.New("Received an incomplete set of fake " +
			"puzzle secrets")
	}

	response := &puzzleSolverResponse{
		promises:  promise.Promises,
		keyHashes: promise.KeyHashes,
		secrets:   secrets.Secrets,
	}

	err = validatePuzzleSolverResponse(challenge, response)
	if err != nil {
		return nil, fmt.Errorf("Failed to validate a puzzle-solver "+
			"challenge response: %v", err)
	}

	keyHashes, err := createPreimageChallanges(challenge, response)
	if err != nil {
		return nil, fmt.Errorf("Failed to create puzzle-solver "+
			"preimage challenges: %v", err)
	}

	con, err := contract.New(tb.chainParams, pp.Amount,
		pp.Epoch+EpochDuration)
	if err != nil {
		return nil, fmt.Errorf("Failed to setup an escrow contract: %v",
			err)
	}

	err = con.SetAddress(contract.SenderAddress, sendAddr, sendPubKey)
	if err != nil {
		return nil, fmt.Errorf("Bad sender address: %v", err)
	}

	refundAddr, refundPubKey, err := w.GetIntAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain a refund address: %v",
			err)
	}
	err = con.SetAddress(contract.RefundAddress, refundAddr, refundPubKey)
	if err != nil {
		return nil, fmt.Errorf("Bad refund address: %v", err)
	}

	if err = w.CreateOffer(ctx, con, keyHashes); err != nil {
		return nil, fmt.Errorf("Failed to create an offer: %v", err)
	}
	if err = w.PublishEscrow(ctx, con); err != nil {
		return nil, fmt.Errorf("Failed to publish an escrow tx: %v", err)
	}

	if err = tb.PaymentOffer(ctx, &PaymentOffer{
		Cookie:            promise.Cookie,
		Amount:            pp.Amount,
		PublicKey:         sendPubKey,
		EscrowHash:        con.EscrowHash,
		EscrowScript:      con.EscrowScript,
		EscrowTransaction: con.EscrowBytes,
		Puzzle:            pp.Puzzle,
		RealPuzzleList:    challenge.realPuzzleList,
		RandomFactors:     challenge.realFactors,
	}); err != nil {
		return nil, fmt.Errorf("Failed to commit purchase: %v", err)
	}

	return &PuzzleSolution{
		Contract: con,
		Solution: nil,
	}, nil
}

func (tb *Tumbler) RedeemEscrow(ctx context.Context, w *wallet.Wallet, pp *PaymentPuzzle, sol *PuzzleSolution) error {
	if err := w.PublishRedeem(ctx, pp.Contract, nil); err != nil {
		return fmt.Errorf("Failed to publish redeeming tx: %v", err)
	}
	return nil
}
