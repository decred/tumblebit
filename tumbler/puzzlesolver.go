// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tumbler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/tumblebit/contract"
	"github.com/decred/tumblebit/puzzle"
)

// SolutionChallenges requests promises of puzzle solutions in order to
// establish ability of the tumbler to solve puzzles obtained from the
// payee.
type SolutionChallenges struct {
	Epoch   int32
	Puzzles [][]byte
}

// PurchasePromise contains solution promises that once unlocked will
// provide solutions to all puzzles specified in the proposal.
type SolutionPromises struct {
	Promises  [][]byte
	KeyHashes [][]byte
}

// GetSolutionPromises obtains cryptographically concealed puzzle solution
// promises.
//
// This marks the start of the Puzzle-Solver protocol where a client learns
// whether or not the tumbler server it's communicating with can provide
// a solution for a puzzle it obtained from the other client.
//
// Without revealing an actual puzzle the client needs to solve, it
// provides a set of potential puzzles, most of which are dummy ones that
// exist only to attest the fairness and indiscriminate nature of the
// server's puzzle solving capabilities.
func (s *Session) GetSolutionPromises(ctx context.Context, sc *SolutionChallenges) (*SolutionPromises, error) {
	var err error

	if ok, err := s.ready(StateSolutionsPromised); !ok {
		return nil, err
	}

	pk, err := s.tb.getPuzzleKey(sc.Epoch)
	if err != nil {
		return nil, err
	}

	solutions := make([][]byte, len(sc.Puzzles))
	promises := make([][]byte, len(sc.Puzzles))
	secrets := make([][]byte, len(sc.Puzzles))
	for i, p := range sc.Puzzles {
		solutions[i], promises[i], secrets[i], err =
			puzzle.NewSolutionPromise(&pk, p)
		if err != nil {
			return nil, err
		}
	}

	// Make a record of submitted puzzles and the locktime.
	s.puzzles = sc.Puzzles
	s.solutions = solutions
	s.secrets = secrets
	s.epoch = sc.Epoch
	// Commit to generated secrets by providing their hash values
	hashes := make([][]byte, len(secrets))
	for i, s := range secrets {
		hashes[i] = chainhash.HashB(s)
	}

	s.state = StateSolutionsPromised
	log.Debugf("Solution promises offered to %s", s.String())

	return &SolutionPromises{
		Promises:  promises,
		KeyHashes: hashes,
	}, nil
}

// PuzzleDisclosure reveals indexes and secret data used to construct
// fictional puzzles that were mixed in into the set in the proposal.
type PuzzleDisclosure struct {
	FakePuzzleList []byte
	FakeFactors    [][]byte
}

// SolutionSecrets provides secret data used to construct promises for
// puzzles identified as fictional by the client and attested by the
// tumbler.
type SolutionSecrets struct {
	Secrets [][]byte
}

// ValidateSolutions obtains the proof that server is fair and indiscriminate.
//
// A client reveals which puzzles in the mix aren't associated with the one
// it needs to solve in order to make a payment. It also lets the tumbler
// know how these puzzles were constructed so that the tumbler can verify
// that all specified puzzles are indeed fake and revealing solutions won't
// let the client accidentally obtain the solution for an actual puzzle.
//
// The client on the other hand learns that the tumbler it's communicating
// with is capable of solving the real puzzle.
func (s *Session) ValidateSolutions(ctx context.Context, pd *PuzzleDisclosure) (*SolutionSecrets, error) {
	if ok, err := s.ready(StateSolutionsValidated); !ok {
		return nil, err
	}

	fakePuzzleList, err := puzzle.DecodeIndexList(pd.FakePuzzleList)
	if err != nil {
		return nil, fmt.Errorf("failed to decode puzzle index list: %v", err)
	}

	if len(fakePuzzleList) > len(s.puzzles) {
		return nil, errors.New("failed to decode puzzle index list: " +
			"bad input values")
	}

	pk, err := s.tb.getPuzzleKey(s.epoch)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a puzzle key for "+
			"epoch %d: %v", s.epoch, err)
	}

	for i, idx := range fakePuzzleList {
		if idx > len(s.puzzles) {
			return nil, errors.New("bad puzzle reference")
		}
		if !puzzle.ValidatePuzzle(pk.PublicKey(), s.puzzles[idx],
			pd.FakeFactors[i]) {
			return nil, errors.New("puzzles didn't verify")
		}
	}

	// Reveal secrets for fake puzzles
	secrets := make([][]byte, len(fakePuzzleList))
	for i, idx := range fakePuzzleList {
		if idx > len(s.secrets) {
			return nil, errors.New("bad puzzle reference")
		}
		secrets[i] = s.secrets[idx]
	}

	s.state = StateSolutionsValidated
	log.Debugf("Solver proof offered to %s", s.String())

	return &SolutionSecrets{
		Secrets: secrets,
	}, nil
}

// PaymentOffer contains a transaction offering escrowed funds for
// puzzle preimages. It needs to be validated and published by the tumbler
// along with a corresponding fulfilling transaction.
//
// PaymentOffer reveals remaining secret data used to construct
// actual puzzles as published on the blockchain by the payer. Tumbler
// must post a solution transaction fulfilling the specified condition.
type PaymentOffer struct {
	Amount         int64
	PublicKey      string
	EscrowHash     []byte
	EscrowScript   []byte
	EscrowTx       []byte
	Puzzle         []byte
	RealPuzzleList []byte
	RealFactors    [][]byte
}

// PaymentOffer validates the offer transaction and records it in the
// ongoing contract. It proceeds to call RevealSolution and PublishSolution
// to reveal and publish hash commitments on the blockchain.
func (s *Session) PaymentOffer(ctx context.Context, po *PaymentOffer) error {
	if ok, err := s.ready(StateOfferReceived); !ok {
		return err
	}

	var err error
	s.realPuzzleList, err = puzzle.DecodeIndexList(po.RealPuzzleList)
	if err != nil {
		return fmt.Errorf("failed to decode puzzle index list: %v", err)
	}
	if len(s.realPuzzleList) > len(s.puzzles) {
		return errors.New("failed to decode puzzle index list: " +
			"bad input values")
	}

	// Make sure there was no previous offer.
	if s.contract != nil {
		return errors.New("conflicting offer tx")
	}

	for _, idx := range s.realPuzzleList {
		if idx > len(s.puzzles) {
			return errors.New("bad puzzle reference")
		}
	}

	if len(po.EscrowTx) == 0 || len(po.EscrowScript) == 0 ||
		len(po.EscrowHash) == 0 {
		return errors.New("bad offer tx")
	}

	s.contract, err = contract.New(s.tb.ChainParams(), po.Amount, s.epoch+
		EpochDuration)
	if err != nil {
		return err
	}
	err = s.contract.SetAddress(contract.SenderAddress, s.address,
		po.PublicKey)
	if err != nil {
		return err
	}

	epochAddr, epochPubKey, err := s.tb.getEpochAddress(ctx, s.epoch)
	if err != nil {
		return fmt.Errorf("failed to obtain an address for an epoch "+
			"%d: %v", s.epoch, err)
	}

	err = s.contract.SetAddress(contract.ReceiverAddress, epochAddr,
		epochPubKey)
	if err != nil {
		return err
	}

	s.contract.EscrowScript = po.EscrowScript
	err = s.tb.wallet.ImportEscrowScript(ctx, s.contract)
	if err != nil {
		return fmt.Errorf("failed to import offer script: %v", err)
	}

	s.state = StateOfferReceived
	log.Debugf("Payment offer received from %s", s.String())

	valid, err := s.tb.wallet.ValidateOffer(ctx, s.contract, po.EscrowHash)
	if err != nil {
		return fmt.Errorf("failed to validate offer tx: %v", err)
	}
	if !valid {
		now := time.Now()
		s.deadline = now.Add(3 * ConfirmationInterval)
		s.tb.DeferAction(s, func(ctx context.Context, s *Session, arg interface{}) {
			po := arg.(*PaymentOffer)
			s.validateOffer(ctx, po)
		}, po, now.Add(ConfirmationInterval))
		return nil
	} else {
		s.validateOffer(ctx, po)
		if s.err != nil {
			return s.err
		}
	}

	return nil
}

// validateOffer is a continuation of the PaymentOffer and it makes sure
// the proposed offer transaction is valid and has been confirmed on the
// blockchain.
func (s *Session) validateOffer(ctx context.Context, po *PaymentOffer) {
	if ok, err := s.ready(StateSolutionPublished); !ok {
		s.err = err
		s.FinalizeExchange(ctx, ReasonFailedExchange, nil)
		return
	}

	valid, err := s.tb.wallet.ValidateOffer(ctx, s.contract,
		po.EscrowHash)
	if err != nil {
		s.err = fmt.Errorf("failed to validate offer tx: %v", err)
		s.FinalizeExchange(ctx, ReasonFailedExchange, nil)
		return
	}
	now := time.Now()
	if !valid && now.After(s.deadline) {
		s.err = fmt.Errorf("offer tx wasn't confirmed after %d seconds",
			3*ConfirmationInterval/time.Second)
		s.FinalizeExchange(ctx, ReasonFailedExchange, nil)
		return
	}
	if !valid {
		s.tb.DeferAction(s, func(ctx context.Context, s *Session, arg interface{}) {
			po := arg.(*PaymentOffer)
			s.validateOffer(ctx, po)
		}, po, now.Add(ConfirmationInterval))
		return
	}

	hashes := make([][]byte, len(s.realPuzzleList))
	for _, idx := range s.realPuzzleList {
		hashes = append(hashes, s.puzzles[idx])
	}

	secrets, err := s.RevealSolution(ctx, po)
	if err != nil {
		s.err = err
		s.FinalizeExchange(ctx, ReasonFailedExchange, nil)
		return
	}

	if err = s.PublishSolution(ctx, secrets); err != nil {
		s.err = err
		s.FinalizeExchange(ctx, ReasonFailedExchange, nil)
		return
	}
}

// RevealSolution completes the Puzzle-Solver protocol and reveals blinding
// factors for the remaining puzzles letting the tumbler know that all of
// them correspond to a single puzzle it requires a solution for.
//
// The tumbler reveals secrets for unlocking puzzles via a fulfilling
// transaction on the blockchain. Secrets MUST NOT be sent to the client.
func (s *Session) RevealSolution(ctx context.Context, po *PaymentOffer) ([][]byte, error) {
	pk, err := s.tb.getPuzzleKey(s.epoch)
	if err != nil {
		return nil, err
	}

	for i, idx := range s.realPuzzleList {
		if idx > len(s.puzzles) {
			return nil, errors.New("bad puzzle reference")
		}
		if !puzzle.ValidateBlindedPuzzle(pk.PublicKey(), s.puzzles[idx],
			po.Puzzle, po.RealFactors[i]) {
			return nil, errors.New("puzzles didn't verify")
		}
	}

	// Reveal secrets for real puzzles
	secrets := make([][]byte, len(s.realPuzzleList))
	for i, idx := range s.realPuzzleList {
		if idx > len(s.secrets) {
			return nil, errors.New("bad puzzle reference")
		}
		secrets[i] = s.secrets[idx]
	}

	return secrets, nil
}

// PublishSolution publishes preimages fulfilling the offer transaction.
func (s *Session) PublishSolution(ctx context.Context, secrets [][]byte) error {
	err := s.tb.wallet.PublishSolution(ctx, s.contract, secrets)
	if err != nil {
		return fmt.Errorf("failed to publish fulfilling tx :%v", err)
	}

	s.state = StateSolutionPublished
	log.Debugf("Solution published for %s", s.String())
	log.Tracef("Solution %s", s.contract.String())

	s.FinalizeExchange(ctx, ReasonSuccess, nil)

	return nil
}
