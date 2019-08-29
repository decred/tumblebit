// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2016-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package netparams

import "github.com/decred/dcrd/chaincfg/v3"

// Params is used to group parameters for various networks such as the main
// network and test networks.
type Params struct {
	*chaincfg.Params
	WalletClientPort  string
	TumblerServerPort string
}

// MainNetParams contains parameters specific running tumblebit and
// dcrd on the main network.
var MainNetParams = Params{
	Params:            chaincfg.MainNetParams(),
	WalletClientPort:  "9111",
	TumblerServerPort: "9191",
}

// TestNet3Params contains parameters specific running tumblebit and
// dcrd on the test network.
var TestNet3Params = Params{
	Params:            chaincfg.TestNet3Params(),
	WalletClientPort:  "19111",
	TumblerServerPort: "19191",
}

// SimNetParams contains parameters specific to the simulation test network
// (wire.SimNet).
var SimNetParams = Params{
	Params:            chaincfg.SimNetParams(),
	WalletClientPort:  "19558",
	TumblerServerPort: "19598",
}
