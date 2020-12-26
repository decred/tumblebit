// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/decred/dcrd/chaincfg/v3"
	pb "github.com/decred/tumblebit/rpc/tumblerrpc"
	"google.golang.org/grpc"
)

type Tumbler struct {
	c pb.TumblerServiceClient

	chainParams *chaincfg.Params
}

func NewTumblerClient(conn *grpc.ClientConn, chainParams *chaincfg.Params) (*Tumbler, error) {
	tb := &Tumbler{
		c:           pb.NewTumblerServiceClient(conn),
		chainParams: chainParams,
	}

	return tb, nil
}

type EscrowRequest struct {
	Address   string
	PublicKey string
	Amount    int64
}

type EscrowOffer struct {
	Cookie            []byte
	Epoch             int32
	LockTime          int32
	Address           string
	PublicKey         string
	EscrowScript      []byte
	EscrowTransaction []byte
}

func (tb *Tumbler) SetupEscrow(ctx context.Context, er *EscrowRequest) (*EscrowOffer, error) {
	ber, err := tb.c.SetupEscrow(ctx, (*pb.SetupEscrowRequest)(er))
	if err != nil {
		return nil, fmt.Errorf("SetupEscrow %v", err)
	}
	return (*EscrowOffer)(ber), nil
}

type SignatureChallenges struct {
	Cookie            []byte
	FakeSetHash       []byte
	RealSetHash       []byte
	TransactionHashes [][]byte
}

type SignaturePromises struct {
	PublicKey []byte
	PuzzleKey []byte
	Puzzles   [][]byte
	Promises  [][]byte
}

func (tb *Tumbler) GetPuzzlePromises(ctx context.Context, sc *SignatureChallenges) (*SignaturePromises, error) {
	ppr, err := tb.c.GetPuzzlePromises(ctx, (*pb.GetPuzzlePromisesRequest)(sc))
	if err != nil {
		return nil, fmt.Errorf("GetPuzzlePromises %v", err)
	}
	return (*SignaturePromises)(ppr), nil
}

type TransactionDisclosure struct {
	Cookie     []byte
	Salt       []byte
	FakeTxList []byte
	RealTxList []byte
	RandomPads [][]byte
}

type SignatureSecrets struct {
	EscrowHash []byte
	Secrets    [][]byte
	Quotients  [][]byte
}

func (tb *Tumbler) FinalizeEscrow(ctx context.Context, cd *TransactionDisclosure) (*SignatureSecrets, error) {
	fer, err := tb.c.FinalizeEscrow(ctx, (*pb.FinalizeEscrowRequest)(cd))
	if err != nil {
		return nil, fmt.Errorf("FinalizeEscrow %v", err)
	}
	return (*SignatureSecrets)(fer), nil
}

type SolutionChallenges struct {
	Address string
	Epoch   int32
	Puzzles [][]byte
}

type SolutionPromises struct {
	Cookie    []byte
	Promises  [][]byte
	KeyHashes [][]byte
}

func (tb *Tumbler) GetSolutionPromises(ctx context.Context, pp *SolutionChallenges) (*SolutionPromises, error) {
	spr, err := tb.c.GetSolutionPromises(ctx, (*pb.GetSolutionPromisesRequest)(pp))
	if err != nil {
		return nil, fmt.Errorf("GetSolutionPromises %v", err)
	}
	return (*SolutionPromises)(spr), nil
}

type PuzzleDisclosure struct {
	Cookie         []byte
	FakePuzzleList []byte
	RandomFactors  [][]byte
}

type SolutionSecrets struct {
	Secrets [][]byte
}

func (tb *Tumbler) ValidateSolutions(ctx context.Context, pd *PuzzleDisclosure) (*SolutionSecrets, error) {
	vsr, err := tb.c.ValidateSolutions(ctx, (*pb.ValidateSolutionsRequest)(pd))
	if err != nil {
		return nil, fmt.Errorf("ValidateSolutions %v", err)
	}
	return (*SolutionSecrets)(vsr), nil
}

type PaymentOffer struct {
	Cookie            []byte
	Amount            int64
	PublicKey         string
	EscrowHash        []byte
	EscrowScript      []byte
	EscrowTransaction []byte
	Puzzle            []byte
	RealPuzzleList    []byte
	RandomFactors     [][]byte
}

func (tb *Tumbler) PaymentOffer(ctx context.Context, po *PaymentOffer) error {
	_, err := tb.c.PaymentOffer(ctx, (*pb.PaymentOfferRequest)(po))
	if err != nil {
		return fmt.Errorf("PaymentOffer %v", err)
	}
	return nil
}
