// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package contract

import (
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
)

// Input/output size estimates.
const (
	// escrowSigScriptSize is the base size of a transaction input script
	// that refunds or redeems a P2SH escrow output.
	// This does not include final push for the contract itself.
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_FALSE
	escrowSigScriptSize = 1 + 73 + 1
)

func sumOutputSerializeSizes(outputs []*wire.TxOut) (serializeSize int) {
	for _, txOut := range outputs {
		serializeSize += txOut.SerializeSize()
	}
	return serializeSize
}

// inputSize returns the size of the transaction input needed to include a
// signature script with size sigScriptSize.  It is calculated as:
//
//   - 32 bytes previous tx
//   - 4 bytes output index
//   - 1 byte tree
//   - 8 bytes amount
//   - 4 bytes block height
//   - 4 bytes block index
//   - Compact int encoding sigScriptSize
//   - sigScriptSize bytes signature script
//   - 4 bytes sequence
func inputSize(sigScriptSize int) int {
	return 32 + 4 + 1 + 8 + 4 + 4 + wire.VarIntSerializeSize(uint64(sigScriptSize)) + sigScriptSize + 4
}

// estimateRefundSerializeSize returns a worst case serialize size estimates
// for a transaction that refunds an escrow P2SH output.
func estimateRefundSerializeSize(contract []byte, txOuts []*wire.TxOut) int {
	contractPush, err := txscript.NewScriptBuilder().AddData(contract).Script()
	if err != nil {
		// Should never be hit since this script does exceed the limits.
		panic(err)
	}
	contractPushSize := len(contractPush)

	// 12 additional bytes are for version, locktime and expiry.
	return 12 + (2 * wire.VarIntSerializeSize(1)) +
		wire.VarIntSerializeSize(1) +
		inputSize(escrowSigScriptSize+contractPushSize) +
		sumOutputSerializeSizes(txOuts)
}

// estimateRedeemSerializeSize returns a worst case serialize size estimates
// for a transaction that redeems an escrow P2SH output.
func estimateRedeemSerializeSize(contract []byte, txOuts []*wire.TxOut, sigScriptAddSize int) int {
	contractPush, err := txscript.NewScriptBuilder().AddData(contract).Script()
	if err != nil {
		// Should never be hit since this script does exceed the limits.
		panic(err)
	}
	contractPushSize := len(contractPush)

	// 12 additional bytes are for version, locktime and expiry.
	return 12 + (2 * wire.VarIntSerializeSize(1)) +
		wire.VarIntSerializeSize(1) +
		inputSize(escrowSigScriptSize+sigScriptAddSize+contractPushSize) +
		sumOutputSerializeSizes(txOuts)
}
