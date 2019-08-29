// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// The tumbler package implements the TumbleBit protocol described in
// https://eprint.iacr.org/2016/575.pdf.
package tumbler

import (
	"container/list"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/tumblebit/puzzle"
	"github.com/decred/tumblebit/wallet"
	"golang.org/x/sync/errgroup"
)

const ConfirmationInterval = 5 * time.Minute

// Tumbler describes an instance of a TumbleBit server.
type Tumbler struct {
	lastEpoch int32

	epochMu sync.RWMutex
	epochs  []*Epoch

	sessMu   sync.RWMutex
	sessions map[[16]byte]*Session

	tickerMu sync.Mutex
	actions  *list.List
	pending  *list.List

	epochDuration    int32
	epochRenewal     int32
	puzzleDifficulty int

	chainParams *chaincfg.Params
	wallet      *wallet.Wallet
}

// Config represents configuration options needed to initialize a tumbler.
type Config struct {
	ChainParams      *chaincfg.Params
	EpochDuration    int32
	EpochRenewal     int32
	PuzzleDifficulty int
	Wallet           *wallet.Wallet
}

// NewTumbler creates a new configured tumbler server object associated
// with a wallet service that provides wallet and blockchain facilities.
func NewTumbler(cfg *Config) *Tumbler {
	t := Tumbler{
		epochDuration:    cfg.EpochDuration,
		epochRenewal:     cfg.EpochRenewal,
		puzzleDifficulty: cfg.PuzzleDifficulty,
		chainParams:      cfg.ChainParams,
		wallet:           cfg.Wallet,
		sessions:         make(map[[16]byte]*Session),
		actions:          list.New(),
		pending:          list.New(),
	}
	return &t
}

func (tb *Tumbler) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return tb.epochCreator(ctx)
	})
	g.Go(func() error {
		return tb.sessionTicker(ctx)
	})
	return g.Wait()
}

// epochCreator is responsible for periodic creation of new epochs to achieve
// an overlapping effect.
func (tb *Tumbler) epochCreator(ctx context.Context) error {
	period := time.Duration(tb.epochRenewal) * ConfirmationInterval
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	log.Infof("Generating epoch every %d seconds", period/time.Second)

	// Create one immediately
	if err := tb.createNewEpoch(); err != nil {
		log.Error(err)
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := tb.createNewEpoch(); err != nil {
				log.Error(err)
				continue
			}
		}
	}
}

var (
	ErrEpochNotFound = errors.New("no such epoch")
)

type Epoch struct {
	addrMu      sync.RWMutex
	Address     string
	Pubkey      string
	BlockHeight int32
	puzzleKey   *puzzle.PuzzleKey
}

// NewEpoch creates a new epoch interval starting at the specified block
// height which acts as a way to lookup existing epochs as well as to expire
// old ones. Each new epoch generates a unique puzzle key.
func (tb *Tumbler) NewEpoch(blockHeight int32) error {
	// Make sure we're not attempting to setup an epoch that would appear
	// older or exactly the same as an existing one.
	if len(tb.epochs) > 0 &&
		tb.epochs[len(tb.epochs)-1].BlockHeight >= blockHeight {
		return fmt.Errorf("bad block height: %d", blockHeight)
	}
	pk, err := puzzle.GeneratePuzzleKey(tb.puzzleDifficulty)
	if err != nil {
		return err
	}
	e := &Epoch{
		BlockHeight: blockHeight,
		puzzleKey:   pk,
	}
	tb.epochMu.Lock()
	// Expire old epochs.
	var n int
	for i, e := range tb.epochs {
		if e.BlockHeight+tb.epochDuration < blockHeight {
			tb.epochs[i] = nil
			n++
		}
	}
	tb.epochs = tb.epochs[n:]
	tb.epochs = append(tb.epochs, e)

	atomic.StoreInt32(&tb.lastEpoch, blockHeight)
	tb.epochMu.Unlock()
	return nil
}

func (tb *Tumbler) createNewEpoch() error {
	blockHeight, err := tb.wallet.CurrentBlockHeight(context.Background())
	if err != nil {
		// XXX: Stop tumbler
		return fmt.Errorf("Wallet failure: %v", err)
	}
	if blockHeight > math.MaxInt32 {
		return fmt.Errorf("Block height is too large: %d", blockHeight)
	}
	err = tb.NewEpoch(int32(blockHeight))
	if err != nil {
		return fmt.Errorf("Failed to setup new epoch: %v", err)
	}
	log.Infof("Created new epoch at block height %d", blockHeight)
	return nil
}

func (tb *Tumbler) getCurrentEpoch() (int32, error) {
	if epoch := atomic.LoadInt32(&tb.lastEpoch); epoch != 0 {
		return epoch, nil
	}
	return 0, errors.New("no current epoch")
}

func (tb *Tumbler) isValidEpoch(blockHeight int32) bool {
	tb.epochMu.RLock()
	for _, e := range tb.epochs {
		if e.BlockHeight == blockHeight {
			tb.epochMu.RUnlock()
			return true
		}
	}
	tb.epochMu.RUnlock()
	return false
}

// getEpochAddress allocates a new external address on demand or returns
// one that was previously allocated.
func (tb *Tumbler) getEpochAddress(ctx context.Context, blockHeight int32) (string, string, error) {
	var epoch *Epoch
	tb.epochMu.RLock()
	for _, e := range tb.epochs {
		if e.BlockHeight == blockHeight {
			if len(e.Address) > 0 {
				address := e.Address
				pubkey := e.Pubkey
				tb.epochMu.RUnlock()
				return address, pubkey, nil
			} else {
				// Don't bother with epochs that are
				// about to expire.
				if e.BlockHeight+tb.epochDuration <
					tb.lastEpoch-1 {
					tb.epochMu.RUnlock()
					return "", "",
						fmt.Errorf("epoch too old: %d",
							blockHeight)
				}
				epoch = e
				break
			}
		}
	}
	tb.epochMu.RUnlock()

	if epoch == nil {
		return "", "", ErrEpochNotFound
	}

	// Lock the epoch we found
	epoch.addrMu.Lock()
	defer epoch.addrMu.Unlock()

	// Make sure noone beat us to it
	if len(epoch.Address) > 0 {
		return epoch.Address, epoch.Pubkey, nil
	}

	// Allocate new external address
	addr, pkey, err := tb.wallet.GetExtAddress(ctx)
	if err != nil {
		return "", "", err
	}
	epoch.Address = addr
	epoch.Pubkey = pkey
	return addr, pkey, nil
}

func (tb *Tumbler) getPuzzleKey(blockHeight int32) (puzzle.PuzzleKey, error) {
	tb.epochMu.RLock()
	defer tb.epochMu.RUnlock()
	for _, e := range tb.epochs {
		if e.BlockHeight == blockHeight {
			return *e.puzzleKey, nil
		}
	}
	return puzzle.PuzzleKey{}, ErrEpochNotFound
}

// ChainParams returns the network parameters for the blockchain
// the tumbler belongs to.
func (tb *Tumbler) ChainParams() *chaincfg.Params {
	return tb.chainParams
}

// Connect associates session with a tumbler service.
func (tb *Tumbler) Connect(s *Session) [16]byte {
	var cookie [16]byte

	s.tb = tb

	tb.sessMu.Lock()
	for {
		rand.Read(cookie[:])
		if _, exists := tb.sessions[cookie]; !exists {
			break
		}
	}
	tb.sessions[cookie] = s
	tb.sessMu.Unlock()

	tb.tickerMu.Lock()
	s.explist = tb.pending.PushBack(s)
	tb.tickerMu.Unlock()

	return cookie
}

// Lookup attempts to locate an active exchange by a cookie.
func (tb *Tumbler) Lookup(key []byte) (*Session, bool) {
	var cookie [16]byte
	copy(cookie[:], key)
	tb.sessMu.RLock()
	s, ok := tb.sessions[cookie]
	tb.sessMu.RUnlock()
	return s, ok
}

// Disconnect removes the session from the lookup table and expiration list.
func (tb *Tumbler) Disconnect(s *Session) {
	tb.sessMu.Lock()
	delete(tb.sessions, s.Cookie)
	tb.sessMu.Unlock()

	tb.tickerMu.Lock()
	tb.removeDeferredActions(s)
	if s.explist != nil {
		tb.pending.Remove(s.explist)
		s.explist = nil
	}
	tb.tickerMu.Unlock()
}

type deferredAction struct {
	session  *Session
	callback func(ctx context.Context, s *Session, arg interface{})
	argument interface{}
	until    time.Time
	entry    *list.Element
}

// DeferAction adds the session to the ticker's list of deferred actions.
// Caller must ensure to provide the s.deferFn function pointer.
func (tb *Tumbler) DeferAction(s *Session, cb func(ctx context.Context, s *Session, arg interface{}), arg interface{}, u time.Time) {
	a := deferredAction{
		session:  s,
		callback: cb,
		argument: arg,
		until:    u,
	}
	tb.tickerMu.Lock()
	tb.actions.PushBack(&a)
	tb.tickerMu.Unlock()
}

// removeDeferredActions removes all deferred actions registered for the
// session.  ticker mutex must be locked by the caller.
func (tb *Tumbler) removeDeferredActions(s *Session) {
	var next *list.Element
	for e := tb.actions.Front(); e != nil; e = next {
		next = e.Next()
		a := e.Value.(*deferredAction)
		if a.session == s {
			tb.actions.Remove(e)
		}
	}
}

func contains(s *Session, list []*Session) bool {
	for i := range list {
		if list[i] == s {
			return true
		}
	}
	return false
}

func (tb *Tumbler) sessionTicker(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	log.Info("Started session ticker coroutine")

	g, ctx := errgroup.WithContext(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Debug("Session ticker cancelled")
			return g.Wait()
		case now := <-ticker.C:
			var actions []*deferredAction
			var expired []*Session
			var next *list.Element

			tb.tickerMu.Lock()
			for e := tb.pending.Front(); e != nil; e = next {
				next = e.Next()
				s := e.Value.(*Session)
				if s.expire.Before(now) {
					tb.pending.Remove(e)
					expired = append(expired, s)
				}
			}
			for e := tb.actions.Front(); e != nil; e = next {
				next = e.Next()
				a := e.Value.(*deferredAction)
				if contains(a.session, expired) {
					tb.actions.Remove(e)
					continue
				}
				if a.until.Before(now) {
					tb.actions.Remove(e)
					actions = append(actions, a)
				}
			}
			tb.tickerMu.Unlock()
			log.Tracef("Session ticker: %d deferred, %d expired",
				len(actions), len(expired))
			if len(actions) > 0 {
				g.Go(func() error {
					return tb.deferredActions(ctx, actions)
				})
			}
			if len(expired) > 0 {
				g.Go(func() error {
					return tb.expireSessions(ctx, expired)
				})
			}
		}
	}
}

func (tb *Tumbler) deferredActions(ctx context.Context, actions []*deferredAction) error {
	for _, a := range actions {
		a.callback(ctx, a.session, a.argument)

		select {
		case <-ctx.Done():
			// XXX: remaining deferred actions aren't processed correctly
			log.Info("Deferred action processing has been cancelled")
			return ctx.Err()
		default:
			continue
		}
	}
	return nil
}

func (tb *Tumbler) expireSessions(ctx context.Context, expired []*Session) error {
	for _, s := range expired {
		s.FinalizeExchange(ctx, ReasonSessionExpired, nil)

		select {
		case <-ctx.Done():
			// XXX: remaining expired sessions aren't finalized correctly
			log.Info("Session expiration process has been cancelled")
			return ctx.Err()
		default:
			continue
		}
	}
	return nil
}
