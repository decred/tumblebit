package tumbler

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/decred/tumblebit/contract"
	"github.com/decred/tumblebit/puzzle"
)

// EscrowRequest asks tumbler to escrow the specified amount redeemable by
// the owner of the public key in case it obtains a correct puzzle solution.
type EscrowRequest struct {
	Address   string
	PublicKey string
	Amount    int64
}

// EscrowOffer presents the client with a signed but not published escrow
// transaction set up for a particular epoch and with a specified locktime.
type EscrowOffer struct {
	Epoch        int32
	LockTime     int32
	Address      string
	PublicKey    string
	EscrowScript []byte
	EscrowTx     []byte
}

// SetupEscrow creates and signs a transaction that escrows tumbler's funds
// for an EpochDuration. The transaction is a P2SH that requires signatures
// from both client and tumbler to transfer escrowed funds to the client.
func (s *Session) SetupEscrow(ctx context.Context, er *EscrowRequest) (*EscrowOffer, error) {
	if ok, err := s.ready(StateEscrowComplete); !ok {
		return nil, err
	}

	epoch, err := s.tb.getCurrentEpoch()
	if err != nil {
		return nil, err
	}

	s.contract, err = contract.New(s.tb.ChainParams(), er.Amount,
		epoch+s.tb.epochDuration)
	if err != nil {
		return nil, err
	}

	if err = s.contract.SetAddress(contract.ReceiverAddress, er.Address,
		er.PublicKey); err != nil {
		return nil, err
	}

	if err = s.tb.wallet.CreateEscrow(ctx, s.contract); err != nil {
		return nil, err
	}
	s.epoch = epoch

	s.state = StateEscrowComplete
	log.Debugf("Escrow setup for %s", s.String())

	return &EscrowOffer{
		Epoch:        epoch,
		LockTime:     epoch + s.tb.epochDuration,
		Address:      s.contract.SenderAddrStr,
		PublicKey:    s.contract.SenderAddr.EncodeAddress(),
		EscrowScript: s.contract.EscrowScript,
		EscrowTx:     s.contract.EscrowBytes,
	}, nil
}

// SignChallengeHashes is a helper function that asks wallet to sign
// challenge hash values. It's not part of GetPuzzlePromises to make
// testing feasible.
func (s *Session) SignChallengeHashes(ctx context.Context, hashes [][]byte) ([][]byte, []byte, error) {
	signatures, pubKey, err := s.tb.wallet.SignHashes(ctx, s.contract, hashes)
	if err != nil {
		return nil, nil, err
	}

	return signatures, pubKey, nil
}

// SignatureChallenges requests signature promises for specified transaction
// hashes, some of which are dummy as indicated by the FakeSetHash as
// opposed to legitimate ones indicated by the RealSetHash. Hash values
// act as a proof that client has included both in the mix.
type SignatureChallenges struct {
	FakeSetHash       []byte
	RealSetHash       []byte
	TransactionHashes [][]byte
	Signatures        [][]byte
	PublicKey         []byte
}

// SignaturePromises contains signature promises for transactions requested
// in SignatureChallenges as well as computational puzzles that unlock
// appropriate promises once solved.
type SignaturePromises struct {
	PublicKey []byte
	PuzzleKey []byte
	Puzzles   [][]byte
	Promises  [][]byte
}

// GetPuzzlePromises obtains cryptographically concealed signature promises.
//
// This marks the starting point for the Puzzle-Promise fairness test where
// TumbleBit server attempts to convince the client that it will correctly
// sign the Cash-out transaction when presented by the client without
// revealing any secret information about the process.
func (s *Session) GetPuzzlePromises(ctx context.Context, cp *SignatureChallenges) (*SignaturePromises, error) {
	if ok, err := s.ready(StatePuzzlesPromised); !ok {
		return nil, err
	}

	pk, err := s.tb.getPuzzleKey(s.epoch)
	if err != nil {
		return nil, err
	}
	key, err := puzzle.MarshalPubKey(&pk)
	if err != nil {
		return nil, err
	}

	puzzles := make([][]byte, len(cp.Signatures))
	promises := make([][]byte, len(cp.Signatures))
	secrets := make([][]byte, len(cp.Signatures))
	for i := range cp.Signatures {
		puzzles[i], promises[i], secrets[i], err =
			puzzle.NewPuzzlePromise(&pk, cp.Signatures[i])
		if err != nil {
			return nil, err
		}
	}

	s.secrets = secrets
	s.realSetHash = cp.RealSetHash
	s.fakeSetHash = cp.FakeSetHash
	s.txHashes = cp.TransactionHashes

	s.state = StatePuzzlesPromised
	log.Debugf("Puzzle promises offered to %s", s.String())

	return &SignaturePromises{
		PublicKey: cp.PublicKey,
		PuzzleKey: key,
		Puzzles:   puzzles,
		Promises:  promises,
	}, nil
}

// TransactionDisclosure reveals secret data used to build dummy transactions
// along with indexes of legitimate and dummy transactions specified in the
// TransactionHashes vector in the proposal.
type TransactionDisclosure struct {
	FakeTxList []byte
	RealTxList []byte
	RandomPads [][]byte
	Salt       []byte
}

// TransactionSecrets provides the required proof that tumbler has signed all
// provided transactions indiscriminately by revealing secret values used
// to construct promises for dummy transactions.
type TransactionSecrets struct {
	Secrets   [][]byte
	Quotients [][]byte
}

// ValidatePuzzles obtains the proof that server is fair and indiscriminate.
//
// A client reveals dummy transactions that were mixed in into the pool of
// potential Cash-out transactions signed by the tumbler. Iff they verify
// as dummy transactions, the tumbler discloses secret values used to
// create associated promises showing its fairness.
//
// Tumbler also creates a proof that it possesses secrets needed to unlock
// remaining puzzles by returning quotients of their secrets that can be
// verified by the client with puzzle.VerifyQuotients.
func (s *Session) ValidatePuzzles(ctx context.Context, cd *TransactionDisclosure) (*TransactionSecrets, error) {
	if ok, err := s.ready(StatePuzzlesValidated); !ok {
		return nil, err
	}

	fakeTxList, err := puzzle.DecodeIndexList(cd.FakeTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to decode fake tx index list: %v",
			err)
	}

	realTxList, err := puzzle.DecodeIndexList(cd.RealTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to decode real tx index list: %v",
			err)
	}

	if (len(fakeTxList) > len(s.txHashes)) ||
		(len(realTxList) > len(s.txHashes)) ||
		(len(cd.RandomPads) > len(s.txHashes)) ||
		(len(fakeTxList) > len(cd.RandomPads)) ||
		(len(cd.Salt) != 32) {
		return nil, errors.New("bad input values")
	}

	pk, err := s.tb.getPuzzleKey(s.epoch)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a puzzle key for "+
			"epoch %d: %v", s.epoch, err)
	}

	// Verify hash of the fake set
	fakeSetHash, err := puzzle.HashIndexList(cd.Salt, fakeTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to hash the fake tx list: %v", err)
	}
	if !bytes.Equal(fakeSetHash, s.fakeSetHash) {
		return nil, errors.New("fake set didn't verify")
	}

	// Verify structure of fake transactions
	for i, idx := range fakeTxList {
		if idx > len(s.txHashes) {
			return nil, errors.New("bad tx reference")
		}
		if len(cd.RandomPads[i]) != 32 {
			return nil, errors.New("bad input values")
		}
		fkh := puzzle.FakeTxFormat(cd.RandomPads[i])
		if !bytes.Equal(fkh, s.txHashes[idx]) {
			return nil, errors.New("fake tx didn't verify")
		}
	}

	// Verify hash of the real set
	realSetHash, err := puzzle.HashIndexList(cd.Salt, realTxList)
	if err != nil {
		return nil, fmt.Errorf("failed to hash the real tx list: %v", err)
	}
	if !bytes.Equal(realSetHash, s.realSetHash) {
		return nil, errors.New("real set didn't verify")
	}

	// Reveal secrets for the fake set
	fakeSecrets := make([][]byte, len(fakeTxList))
	for i, idx := range fakeTxList {
		fakeSecrets[i] = s.secrets[idx]
	}

	// Prepare quotients to verify puzzles for the real set
	realSecrets := make([][]byte, len(realTxList))
	for i, idx := range realTxList {
		if idx > len(s.secrets) {
			return nil, errors.New("bad tx reference")
		}
		realSecrets[i] = s.secrets[idx]
	}
	quotients, err := puzzle.Quotients(pk.PublicKey(), realSecrets)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quotients: %v", err)
	}

	// Garbage-collect cached puzzles, tx hashes, ets.
	s.puzzles = nil
	s.txHashes = nil
	s.realSetHash = nil
	s.fakeSetHash = nil

	s.state = StatePuzzlesValidated
	log.Debugf("Promise proof offered to %s", s.String())

	return &TransactionSecrets{
		Secrets:   fakeSecrets,
		Quotients: quotients,
	}, nil
}

// FinalizeEscrow publishes the escrow transaction onto the blockchain.
func (s *Session) FinalizeEscrow(ctx context.Context) ([]byte, error) {
	if ok, err := s.ready(StateEscrowPublished); !ok {
		return nil, err
	}

	if err := s.tb.wallet.PublishEscrow(ctx, s.contract); err != nil {
		return nil, fmt.Errorf("failed to publish escrow tx :%v", err)
	}

	s.state = StateEscrowPublished
	log.Debugf("Escrow published for %s", s.String())
	log.Tracef("Escrow %s", s.contract.String())

	// Defer to safely return the escrow tx hash
	defer s.FinalizeExchange(ctx, ReasonSuccess, nil)

	return s.contract.EscrowHash, nil
}
