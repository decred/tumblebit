// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/tumblebit/netparams"
	"github.com/decred/tumblebit/wallet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var activeNet = &netparams.MainNetParams

const (
	showHelpMessage = "Specify -h to show available options"
	listCmdMessage  = "Specify -l to list available commands"
)

// usage displays the general usage when the help flag is not displayed and
// and an invalid command was specified.  The commandUsage function is used
// instead when a valid command was specified.
func usage(errorMessage string) {
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	fmt.Fprintln(os.Stderr, errorMessage)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  %s [OPTIONS] <command> <args...>\n\n",
		appName)
	fmt.Fprintln(os.Stderr, showHelpMessage)
	fmt.Fprintln(os.Stderr, listCmdMessage)
}

func main() {
	cfg, args, err := loadConfig()
	if err != nil {
		os.Exit(1)
	}

	if len(args) < 1 {
		usage("No command specified")
		os.Exit(1)
	}

	// Create a context that is cancelled when a shutdown request is received
	// through an interrupt signal or an RPC request.
	ctx := withShutdownCancel(context.Background())
	go shutdownListener()

	tb, err := connectTumbler(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	w, err := connectWallet(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	puzzle, err := tb.NewEscrow(ctx, w)
	if err != nil {
		log.Fatalf("Failed to setup escrow: %v", err)
	}
	solution, err := tb.MakePayment(ctx, w, puzzle)
	if err != nil {
		log.Fatalf("Failed to make payment: %v", err)
	}
	err = tb.RedeemEscrow(ctx, w, puzzle, solution)
	if err != nil {
		log.Fatalf("Failed to redeem escrow: %v", err)
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

func connectTumbler(ctx context.Context, cfg *config) (*Tumbler, error) {
	conn, err := startRPCClient(ctx, cfg.TumblerRPCServer,
		cfg.TumblerRPCCert, !cfg.NoTLS)
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to the TumbleBit RPC "+
			"server: %v", err)
	}
	//defer conn.Close()

	if done(ctx) {
		return nil, ctx.Err()
	}

	tb, err := NewTumblerClient(conn, activeNet.Params)
	if err != nil {
		return nil, fmt.Errorf("Unable to setup a gRPC client session: "+
			"%v", err)
	}

	return tb, nil
}

func connectWallet(ctx context.Context, cfg *config) (*wallet.Wallet, error) {
	conn, err := startRPCClient(ctx, cfg.WalletRPCServer,
		cfg.WalletRPCCert, !cfg.NoTLS)
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to the TumbleBit RPC "+
			"server: %v", err)
	}
	//defer conn.Close()

	if done(ctx) {
		return nil, ctx.Err()
	}

	walletCfg := wallet.Config{
		Account:          cfg.Account,
		AccountName:      cfg.AccountName,
		ChainParams:      activeNet.Params,
		WalletConnection: conn,
		WalletPassword:   cfg.WalletPassword,
	}

	w, err := wallet.New(ctx, &walletCfg)
	if err != nil {
		return nil, fmt.Errorf("Unable to setup a gRPC client session: "+
			"%v", err)
	}

	return w, nil
}

func startRPCClient(ctx context.Context, remote, ca string, tls bool) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	if tls {
		host, _, err := net.SplitHostPort(remote)
		if err != nil {
			return nil, err
		}
		creds, err := credentials.NewClientTLSFromFile(ca, host)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	opts = append(opts, grpc.WithBlock())

	conn, err := grpc.DialContext(ctx, remote, opts...)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
