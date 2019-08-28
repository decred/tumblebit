// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package rpcserver implements the RPC API and is used by the main package to
// start gRPC services.
//
// Full documentation of the API implemented by this package is maintained in a
// language-agnostic document:
//
//   https://github.com/decred/dcrwallet/blob/master/rpc/documentation/api.md
//
// Any API changes must be performed according to the steps listed here:
//
//   https://github.com/decred/dcrwallet/blob/master/rpc/documentation/serverchanges.md
package rpcserver

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/decred/tumblebit/rpc/tumblerrpc"
	"github.com/decred/tumblebit/tumbler"
)

// Public API version constants
const (
	semverString = "0.1.0"
	semverMajor  = 0
	semverMinor  = 1
	semverPatch  = 0
)

// versionServer provides RPC clients with the ability to query the RPC server
// version.
type versionServer struct{}

// tumblerServer provides tumbler services for RPC clients.
type tumblerServer struct {
	ready   uint32 // atomic
	tumbler *tumbler.Tumbler
}

// Singleton implementations of each service.  Not all services are immediately
// usable.
var (
	versionService versionServer
	tumblerService tumblerServer
)

// RegisterServices registers implementations of each gRPC service and registers
// it with the server.  Not all service are ready to be used after registration.
func RegisterServices(server *grpc.Server) {
	pb.RegisterVersionServiceServer(server, &versionService)
	pb.RegisterTumblerServiceServer(server, &tumblerService)
}

var serviceMap = map[string]interface{}{
	"tumblerrpc.VersionService": &versionService,
	"tumblerrpc.TumblerService": &tumblerService,
}

// ServiceReady returns nil when the service is ready and a gRPC error when not.
func ServiceReady(service string) error {
	s, ok := serviceMap[service]
	if !ok {
		return status.Errorf(codes.Unimplemented, "service %s not found", service)
	}
	type readyChecker interface {
		checkReady() bool
	}
	ready := true
	r, ok := s.(readyChecker)
	if ok {
		ready = r.checkReady()
	}
	if !ready {
		return status.Errorf(codes.FailedPrecondition, "service %v is not ready", service)
	}
	return nil
}

func (*versionServer) Version(ctx context.Context, req *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{
		VersionString: semverString,
		Major:         semverMajor,
		Minor:         semverMinor,
		Patch:         semverPatch,
	}, nil
}

// StartTumblerService starts the TumblerService.
func StartTumblerService(server *grpc.Server, tumbler *tumbler.Tumbler) {
	tumblerService.tumbler = tumbler
	if atomic.SwapUint32(&tumblerService.ready, 1) != 0 {
		panic("service already started")
	}
}

var (
	// ErrInProgress must be returned when concurrent access is requested.
	ErrInProgress = status.Errorf(codes.Aborted, "operation in progress")

	// ErrBadCookie can be returned to let clients know their session has
	// already expired.
	ErrBadCookie = status.Errorf(codes.InvalidArgument, "bad cookie")

	// ErrTempFailure can be returned to indicate a temporary nature of an
	// error, prompting the client to try again later.
	ErrTempFailure = status.Errorf(codes.Internal, "temporary failure")

	// ErrBadAddress must be returned to indicate that client has supplied
	// an invalid address.
	ErrBadAddress = status.Errorf(codes.InvalidArgument, "bad address")

	// ErrEscrowFailed must be returned to indicate that the resource is
	// unavailable.
	ErrEscrowFailed = status.Errorf(codes.Unavailable, "escrow failed")

	// ErrBadRequest is a vague error message that must be returned during
	// the exchange to obscure which step has actually failed.
	ErrBadRequest = status.Errorf(codes.FailedPrecondition, "bad request")
)

func (ts *tumblerServer) checkReady() bool {
	return atomic.LoadUint32(&ts.ready) != 0
}

func (ts *tumblerServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{}, nil
}

func (ts *tumblerServer) SetupEscrow(ctx context.Context, req *pb.SetupEscrowRequest) (*pb.SetupEscrowResponse, error) {
	if len(req.Address) == 0 {
		return nil, ErrBadAddress
	}

	s := tumbler.NewSession(ts.tumbler, req.Address)

	escrow, err := s.SetupEscrow(ctx, &tumbler.EscrowRequest{
		Address:   req.Address,
		PublicKey: req.PublicKey,
		Amount:    req.Amount,
	})
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonFailedExchange, err)
		return nil, ErrEscrowFailed
	}

	return &pb.SetupEscrowResponse{
		Cookie:            s.Cookie[:],
		Epoch:             escrow.Epoch,
		LockTime:          escrow.LockTime,
		Address:           escrow.Address,
		PublicKey:         escrow.PublicKey,
		EscrowScript:      escrow.EscrowScript,
		EscrowTransaction: escrow.EscrowTx,
	}, nil
}

func (ts *tumblerServer) GetPuzzlePromises(ctx context.Context, req *pb.GetPuzzlePromisesRequest) (*pb.GetPuzzlePromisesResponse, error) {
	s, ok := ts.tumbler.Lookup(req.Cookie)
	if !ok {
		return nil, ErrBadCookie
	}
	if !s.TryLock() {
		return nil, ErrInProgress
	}
	defer s.Unlock()

	signatures, pubKey, err := s.SignChallengeHashes(ctx, req.TransactionHashes)
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonInternalError, err)
		return nil, ErrTempFailure
	}

	promise, err := s.GetPuzzlePromises(ctx, &tumbler.SignatureChallenges{
		FakeSetHash:       req.FakeSetHash,
		RealSetHash:       req.RealSetHash,
		TransactionHashes: req.TransactionHashes,
		Signatures:        signatures,
		PublicKey:         pubKey,
	})
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonFailedExchange, err)
		return nil, ErrBadRequest
	}

	return &pb.GetPuzzlePromisesResponse{
		PublicKey: promise.PublicKey,
		PuzzleKey: promise.PuzzleKey,
		Puzzles:   promise.Puzzles,
		Promises:  promise.Promises,
	}, nil
}

func (ts *tumblerServer) FinalizeEscrow(ctx context.Context, req *pb.FinalizeEscrowRequest) (*pb.FinalizeEscrowResponse, error) {
	s, ok := ts.tumbler.Lookup(req.Cookie)
	if !ok {
		return nil, ErrBadCookie
	}
	if !s.TryLock() {
		return nil, ErrInProgress
	}
	defer s.Unlock()

	secrets, err := s.ValidatePuzzles(ctx, &tumbler.TransactionDisclosure{
		FakeTxList: req.FakeTxList,
		RealTxList: req.RealTxList,
		RandomPads: req.RandomPads,
		Salt:       req.Salt,
	})
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonFailedExchange, err)
		return nil, ErrBadRequest
	}

	escrowHash, err := s.FinalizeEscrow(ctx)
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonFailedExchange, err)
		return nil, ErrBadRequest
	}

	return &pb.FinalizeEscrowResponse{
		EscrowHash: escrowHash,
		Secrets:    secrets.Secrets,
		Quotients:  secrets.Quotients,
	}, nil
}

func (ts *tumblerServer) GetSolutionPromises(ctx context.Context, req *pb.GetSolutionPromisesRequest) (*pb.GetSolutionPromisesResponse, error) {
	if len(req.Address) == 0 {
		return nil, ErrBadAddress
	}

	s := tumbler.NewSession(ts.tumbler, req.Address)

	promise, err := s.GetSolutionPromises(ctx, &tumbler.SolutionChallenges{
		Epoch:   req.Epoch,
		Puzzles: req.Puzzles,
	})
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonFailedExchange, err)
		return nil, ErrBadRequest
	}

	return &pb.GetSolutionPromisesResponse{
		Cookie:    s.Cookie[:],
		Promises:  promise.Promises,
		KeyHashes: promise.KeyHashes,
	}, nil
}

func (ts *tumblerServer) ValidateSolutions(ctx context.Context, req *pb.ValidateSolutionsRequest) (*pb.ValidateSolutionsResponse, error) {
	s, ok := ts.tumbler.Lookup(req.Cookie)
	if !ok {
		return nil, ErrBadCookie
	}
	if !s.TryLock() {
		return nil, ErrInProgress
	}
	defer s.Unlock()

	secrets, err := s.ValidateSolutions(ctx, &tumbler.PuzzleDisclosure{
		FakePuzzleList: req.FakePuzzleList,
		FakeFactors:    req.RandomFactors,
	})
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonFailedExchange, err)
		return nil, ErrBadRequest
	}

	return &pb.ValidateSolutionsResponse{
		Secrets: secrets.Secrets,
	}, nil
}

func (ts *tumblerServer) PaymentOffer(ctx context.Context, req *pb.PaymentOfferRequest) (*pb.PaymentOfferResponse, error) {
	s, ok := ts.tumbler.Lookup(req.Cookie)
	if !ok {
		return nil, ErrBadCookie
	}
	if !s.TryLock() {
		return nil, ErrInProgress
	}
	defer s.Unlock()

	err := s.PaymentOffer(ctx, &tumbler.PaymentOffer{
		Amount:         req.Amount,
		PublicKey:      req.PublicKey,
		EscrowHash:     req.EscrowHash,
		EscrowScript:   req.EscrowScript,
		EscrowTx:       req.EscrowTransaction,
		Puzzle:         req.Puzzle,
		RealPuzzleList: req.RealPuzzleList,
		RealFactors:    req.RandomFactors,
	})
	if err != nil {
		s.FinalizeExchange(ctx, tumbler.ReasonFailedExchange, err)
		return nil, ErrBadRequest
	}

	return &pb.PaymentOfferResponse{}, nil
}
