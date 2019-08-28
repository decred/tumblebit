// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"os"
	"runtime"

	"github.com/decred/tumblebit/rpc/rpcserver"
	"github.com/decred/tumblebit/tumbler"
	"github.com/decred/tumblebit/version"
	"github.com/decred/tumblebit/wallet"
)

var (
	cfg *config
)

func main() {
	// Create a context that is cancelled when a shutdown request is received
	// through an interrupt signal or an RPC request.
	ctx := withShutdownCancel(context.Background())
	go shutdownListener()

	// Run the server until permanent failure or shutdown is requested.
	if err := run(ctx); err != nil && err != context.Canceled {
		os.Exit(1)
	}
}

// done returns whether the context's Done channel was closed due to
// cancellation or exceeded deadline.
func done(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// run is the main startup and teardown logic performed by the main package.
func run(ctx context.Context) error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	tcfg, _, err := loadConfig(ctx)
	if err != nil {
		return err
	}
	cfg = tcfg
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// Show version at startup.
	log.Infof("Version %s (Go version %s)", version.String(), runtime.Version())

	if done(ctx) {
		return ctx.Err()
	}

	// Connect to the wallet RPC service
	walletClient, err := startRPCClient(ctx)
	if err != nil {
		log.Errorf("Unable to connect to the wallet service: %v", err)
		return err
	}
	defer walletClient.Close()

	if done(ctx) {
		return ctx.Err()
	}

	walletCfg := wallet.Config{
		Account:          cfg.Account,
		AccountName:      cfg.AccountName,
		ChainParams:      activeNet.Params,
		WalletConnection: walletClient,
		WalletPassword:   cfg.WalletPassword,
	}

	// Create a wallet communication object
	w, err := wallet.New(ctx, &walletCfg)
	if err != nil {
		log.Errorf("Failed to communicate with the wallet: %v", err)
		return err
	}

	if done(ctx) {
		return ctx.Err()
	}

	tumblerCfg := tumbler.Config{
		ChainParams:      activeNet.Params,
		EpochDuration:    cfg.EpochDuration,
		EpochRenewal:     cfg.EpochRenewal,
		PuzzleDifficulty: cfg.PuzzleDifficulty,
		Wallet:           w,
	}

	// Create and start the RPC server to serve client connections.
	tumblerServer, err := startRPCServer()
	if err != nil {
		log.Errorf("Unable to create a Tumbler server: %v", err)
		return err
	}

	tb := tumbler.NewTumbler(&tumblerCfg)

	if tumblerServer != nil {
		// Start tumbler gRPC services.
		rpcserver.StartTumblerService(tumblerServer, tb)
		defer func() {
			log.Warn("Stopping gRPC server...")
			tumblerServer.Stop()
			log.Info("gRPC server shutdown")
		}()
	}

	// Fire up the TumbleBit server
	err = tb.Run(ctx)
	switch err {
	case nil:
		log.Info("TumbleBit service stopped")
	case context.Canceled:
		log.Error("TumbleBit service cancelled")
	default:
		log.Errorf("Failed to setup a TumbleBit service: %v", err)
		return err
	}

	// Wait until shutdown is signaled before returning and running deferred
	// shutdown tasks.
	<-ctx.Done()
	return ctx.Err()
}
