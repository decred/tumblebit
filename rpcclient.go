// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func startRPCClient(ctx context.Context) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	if !cfg.DisableClientTLS {
		host, _, err := net.SplitHostPort(cfg.RPCConnect)
		if err != nil {
			return nil, err
		}
		creds, err := credentials.NewClientTLSFromFile(cfg.CAFile.Value, host)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	client, err := grpc.DialContext(ctx, cfg.RPCConnect, opts...)
	if err != nil {
		return nil, err
	}

	return client, nil
}
