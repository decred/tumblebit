// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tumbler

import (
	"container/list"
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/decred/tumblebit/contract"
)

const (
	// Initial state
	StateInitial = iota
	// Payee states
	StateEscrowComplete
	StatePuzzlesPromised
	StatePuzzlesValidated
	StateEscrowPublished
	MaxPayeeState
	// Payer states
	StateSolutionsPromised
	StateSolutionsValidated
	StateOfferReceived
	StateSolutionPublished
	MaxPayerState
)

var stateNames = [...]string{
	StateInitial:            "InitialState",
	StateEscrowComplete:     "EscrowComplete",
	StatePuzzlesPromised:    "PuzzlesPromised",
	StatePuzzlesValidated:   "PuzzlesValidated",
	StateEscrowPublished:    "EscrowPublished",
	MaxPayeeState:           "MaxPayeeState",
	StateSolutionsPromised:  "SolutionsPromised",
	StateSolutionsValidated: "SolutionsValidated",
	StateOfferReceived:      "OfferReceived",
	StateSolutionPublished:  "SolutionPublished",
	MaxPayerState:           "MaxPayerState",
}

const (
	// Exchange has completed successfully
	ReasonSuccess = iota
	// Aborting due to a session expiration timeout
	ReasonSessionExpired
	// Aborting due to a issue during exchange
	ReasonFailedExchange
	// Aborting due to an internal error (i.e. broken RPC connection)
	ReasonInternalError
)

var reasonNames = [...]string{
	ReasonSuccess:        "exchange was completed",
	ReasonSessionExpired: "expiration timeout",
	ReasonFailedExchange: "exchange error",
	ReasonInternalError:  "internal error",
}

// Session keeps state of the exchange with a connected client.
type Session struct {
	sersema int32 // Serialization semaphore
	finsema int32 // Finalization semaphore

	Cookie [16]byte // Identification cookie

	tb       *Tumbler      // Associated Tumbler
	explist  *list.Element // Expire list element
	expire   time.Time     // When to expire
	deadline time.Time     // Cumulative deadline for all deferred actions

	address  string             // Client's external address
	epoch    int32              // Selected epoch
	contract *contract.Contract // Contract in progress
	state    int                // Current state of the exchange
	err      error              // Asynchronous error

	// Puzzles that are being currently negotiated.
	puzzles   [][]byte
	secrets   [][]byte
	solutions [][]byte
	txHashes  [][]byte
	// realSet and fakeSet are salted BLAKE2s-256 hashes.
	realSetHash []byte
	fakeSetHash []byte
	// realPuzzleList caches decoded values
	realPuzzleList []int
}

// NewSession creates a new Session object with a provided address.
func NewSession(tb *Tumbler, address string) *Session {
	s := Session{
		address: address,
		tb:      tb,
	}

	s.Cookie = tb.Connect(&s)

	// Conservative expiration timeout
	s.expire = time.Now().Add((EpochDuration + 1) * ConfirmationInterval)

	log.Infof("New session for %s", s.String())

	return &s
}

func (s *Session) ready(next int) (bool, error) {
	switch s.state {
	case StateInitial:
		if next == StateEscrowComplete || next == StateSolutionsPromised {
			return true, nil
		}
	case StateEscrowPublished, StateSolutionPublished:
		return false, fmt.Errorf("cannot advance past the final stage: "+
			"requested %s", stateNames[next])
	default:
		if next == s.state+1 {
			return true, nil
		}
	}
	return false, fmt.Errorf("not ready to advance to %s from %s",
		stateNames[next], stateNames[s.state])
}

func (s *Session) FinalizeExchange(ctx context.Context, reason int, details error) {
	// XXX: Perform final cleanup depending on the state of the contract.
	if reason == ReasonSuccess && (s.state != StateEscrowPublished &&
		s.state != StateSolutionPublished) {
		panic("no reason for success")
	}

	// Make sure only one finalization process is running
	if !atomic.CompareAndSwapInt32(&s.finsema, 0, 1) {
		return
	}

	s.tb.Disconnect(s)

	logf := log.Info
	message := fmt.Sprintf("Finalizing exchange for %s", s.String())
	if reason != ReasonSuccess {
		logf = log.Warn
		message += fmt.Sprintf(" due to %s", reasonNames[reason])
	}
	if details != nil {
		message += fmt.Sprintf(": %v", details)
	}
	if s.err != nil {
		message += fmt.Sprintf(": %v", s.err)
	}
	logf(message)
}

// TryLock attempts to acquire the semaphore and returns true if successful
// and false otherwise.
func (s *Session) TryLock() bool {
	return atomic.CompareAndSwapInt32(&s.sersema, 0, 1)
}

// Unlock releases the semaphore but panics if it was already released.
func (s *Session) Unlock() {
	if atomic.SwapInt32(&s.sersema, 0) == 0 {
		panic("semaphore was already released")
	}
}

func (s *Session) String() string {
	if len(s.address) == 0 {
		return "not initialized"
	}
	str := fmt.Sprintf("%s id %x state %s", s.address, s.Cookie,
		stateNames[s.state])
	if !s.expire.IsZero() {
		now := time.Now()
		if s.expire.Before(now) {
			str += " expired "
		} else {
			str += " expires "
		}
		str += s.expire.Format("2006-01-02 15:04:05.999")
	}
	return str
}
