// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/tumblebit/contract"
)

func redeemTxHash(con *contract.Contract) ([]byte, error) {
	return txscript.CalcSignatureHash(con.EscrowScript, txscript.SigHashAll,
		con.RedeemTx, 0, nil)
}
