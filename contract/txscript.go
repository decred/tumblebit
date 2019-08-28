// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package contract

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/wallet/txrules"
)

const feePerKb = 1e5

const verifyFlags = txscript.ScriptBip16 |
	txscript.ScriptVerifyDERSignatures |
	txscript.ScriptVerifyStrictEncoding |
	txscript.ScriptVerifyMinimalData |
	txscript.ScriptDiscourageUpgradableNops |
	txscript.ScriptVerifyCleanStack |
	txscript.ScriptVerifyCheckLockTimeVerify |
	txscript.ScriptVerifyCheckSequenceVerify |
	txscript.ScriptVerifyLowS |
	txscript.ScriptVerifySHA256

func (con *Contract) AddEscrowScript() error {
	var err error

	con.EscrowScript, err = buildEscrowContract(con.SenderScriptAddr,
		con.ReceiverScriptAddr, int64(con.LockTime))
	if err != nil {
		return fmt.Errorf("failed to compose escrow contract: %v", err)
	}
	con.EscrowAddr, err = dcrutil.NewAddressScriptHash(con.EscrowScript,
		con.ChainParams)
	con.EscrowAddrStr = con.EscrowAddr.String()
	if err != nil {
		return fmt.Errorf("failed to generate a new script hash: %v", err)
	}
	con.EscrowPayScript, err = txscript.PayToAddrScript(con.EscrowAddr)
	if err != nil {
		return fmt.Errorf("failed to create a new script address: %v", err)
	}
	return nil
}

// buildEscrowContract returns an output script that may be redeemed by one
// of two signature scripts:
//
//   <payer sig> <redeemer sig> 1
//
//   <payer sig> 0
//
// The first signature script is the normal redemption path done by the
// other party and requires both tumbler and client signatures. The second
// signature script is the refund path performed by us, but the refund can
// only be performed after locktime.
func buildEscrowContract(pkPayer, pkRedeemer []byte, locktime int64) ([]byte, error) {
	b := txscript.NewScriptBuilder()

	b.AddOp(txscript.OP_IF) // Normal redeem path
	{
		// Check 2-of-2 multisig.
		b.AddOp(txscript.OP_2)
		b.AddData(pkPayer)
		b.AddData(pkRedeemer)
		b.AddOp(txscript.OP_2)
		b.AddOp(txscript.OP_CHECKMULTISIG)
	}
	b.AddOp(txscript.OP_ELSE) // Refund path
	{
		// Verify locktime and drop it off the stack (which is not done
		// by CLTV).
		b.AddInt64(locktime)
		b.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
		b.AddOp(txscript.OP_DROP)

		// Verify our signature is being used to redeem the output.
		b.AddData(pkPayer)
		b.AddOp(txscript.OP_CHECKSIG)
	}
	b.AddOp(txscript.OP_ENDIF)

	return b.Script()
}

func (con *Contract) AddOfferScript(hashes [][]byte, hashOp byte) error {
	var err error

	con.EscrowScript, err = buildOfferContract(con.SenderScriptAddr,
		con.ReceiverScriptAddr, hashes, hashOp, int64(con.LockTime))
	if err != nil {
		return fmt.Errorf("failed to compose escrow contract: %v", err)
	}
	con.EscrowAddr, err = dcrutil.NewAddressScriptHash(con.EscrowScript,
		con.ChainParams)
	con.EscrowAddrStr = con.EscrowAddr.String()
	if err != nil {
		return fmt.Errorf("failed to generate a new script hash: %v", err)
	}
	con.EscrowPayScript, err = txscript.PayToAddrScript(con.EscrowAddr)
	if err != nil {
		return fmt.Errorf("failed to create a new script address: %v", err)
	}
	return nil
}

// buildOfferContract returns an output script that may be redeemed by one
// of two signature scripts:
//
//   OP_RIPEMD160, h1, OP_EQUALVERIFY
//   OP_RIPEMD160, h2, OP_EQUALVERIFY
//   ...
//   <redeemer sig> 1
//
//  Or:
//
//   <payer sig> 0
//
// The first signature script is the normal redemption path done by the
// other party and requires hash preimages and a tumbler signature. The
// second signature script is the refund path performed by the client,
// but the refund can only be performed after locktime.
func buildOfferContract(pkPayer, pkRedeemer []byte, hashes [][]byte, hashOp byte, locktime int64) ([]byte, error) {
	b := txscript.NewScriptBuilder()

	b.AddOp(txscript.OP_IF) // Normal redeem path
	{
		for _, h := range hashes {
			b.AddOp(hashOp)
			b.AddData(h)
			b.AddOp(txscript.OP_EQUALVERIFY)
		}
		// Check redeemer's signature.
		b.AddData(pkRedeemer)
		b.AddOp(txscript.OP_CHECKSIG)
	}
	b.AddOp(txscript.OP_ELSE) // Refund path
	{
		// Verify locktime and drop it off the stack (which is not done
		// by CLTV).
		b.AddInt64(locktime)
		b.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
		b.AddOp(txscript.OP_DROP)

		// Verify our signature is being used to redeem the output.
		b.AddData(pkPayer)
		b.AddOp(txscript.OP_CHECKSIG)
	}
	b.AddOp(txscript.OP_ENDIF)

	return b.Script()
}

// BuildRefundTx creates a refund transaction that spends escrowed funds.
func (con *Contract) BuildRefundTx() error {
	var err error

	// XXX: temporary compat with the old code
	if con.EscrowTx == nil {
		var tx wire.MsgTx
		err = tx.Deserialize(bytes.NewReader(con.EscrowBytes))
		if err != nil {
			return fmt.Errorf("failed to deserialize escrow tx: %v", err)
		}
		con.EscrowTx = &tx
	}

	contractOutPoint := wire.OutPoint{
		Hash:  con.EscrowTx.TxHash(),
		Index: ^uint32(0),
	}
	for i, o := range con.EscrowTx.TxOut {
		if bytes.Equal(o.PkScript, con.EscrowPayScript) {
			contractOutPoint.Index = uint32(i)
			break
		}
	}
	if contractOutPoint.Index == ^uint32(0) {
		return errors.New("contract tx does not contain a P2SH contract payment")
	}

	refundOutScript, err := txscript.PayToAddrScript(con.RefundAddr)
	if err != nil {
		return err
	}

	tx := wire.NewMsgTx()
	tx.LockTime = uint32(con.LockTime)
	tx.AddTxOut(wire.NewTxOut(0, refundOutScript)) // amount set below
	refundSize := estimateRefundSerializeSize(con.EscrowScript,
		tx.TxOut)
	refundFee := txrules.FeeForSerializeSize(feePerKb, refundSize)
	tx.TxOut[0].Value = con.EscrowTx.TxOut[contractOutPoint.Index].Value -
		int64(refundFee)
	if txrules.IsDustOutput(tx.TxOut[0], feePerKb) {
		return fmt.Errorf("refund output value of %v is dust",
			dcrutil.Amount(tx.TxOut[0].Value))
	}

	txIn := wire.NewTxIn(&contractOutPoint, nil)
	txIn.Sequence = 0
	tx.AddTxIn(txIn)

	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)

	con.RefundTx = tx
	con.RefundBytes = buf.Bytes()

	return nil
}

// AddRefundScript creates a refund script to complete the escrow script.
func (con *Contract) AddRefundScript() error {
	var err error

	con.RefundScript, err = refundP2SHContract(con.EscrowScript,
		con.RefundSig)
	if err != nil {
		return fmt.Errorf("failed to compose a refund contract: %v", err)
	}
	con.RefundTx.TxIn[0].SignatureScript = con.RefundScript

	var buf bytes.Buffer
	buf.Grow(con.RefundTx.SerializeSize())

	con.RefundTx.Serialize(&buf)
	con.RefundBytes = buf.Bytes()

	return nil
}

// VerifyRefundTx makes sure that resulting refund script executes correctly.
func (con *Contract) VerifyRefundTx() error {
	contractOutPoint := wire.OutPoint{
		Hash:  con.EscrowTx.TxHash(),
		Index: ^uint32(0),
	}
	for i, o := range con.EscrowTx.TxOut {
		if bytes.Equal(o.PkScript, con.EscrowPayScript) {
			contractOutPoint.Index = uint32(i)
			break
		}
	}

	e, err := txscript.NewEngine(
		con.EscrowTx.TxOut[contractOutPoint.Index].PkScript,
		con.RefundTx, 0, verifyFlags, txscript.DefaultScriptVersion,
		txscript.NewSigCache(10))
	if err != nil {
		return err
	}
	if err = e.Execute(); err != nil {
		return err
	}
	return nil
}

// refundP2SHContract returns the signature script to refund a contract
// output using the contract author's signature after the locktime has
// been reached. This function assumes P2SH and appends the contract as
// the final data push.
func refundP2SHContract(contract, sig []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddData(sig)
	b.AddInt64(0)
	b.AddData(contract)
	return b.Script()
}

func (con *Contract) BuildRedeemTx(sigScriptAddSize int) error {
	var err error

	// XXX: temporary compat with the old code
	if con.EscrowTx == nil {
		var tx wire.MsgTx
		err = tx.Deserialize(bytes.NewReader(con.EscrowBytes))
		if err != nil {
			return fmt.Errorf("failed to deserialize escrow tx: %v", err)
		}
		con.EscrowTx = &tx
	}

	contractHash := dcrutil.Hash160(con.EscrowScript)
	contractOut := -1
	for i, out := range con.EscrowTx.TxOut {
		sc, addrs, _, _ := txscript.ExtractPkScriptAddrs(out.Version,
			out.PkScript, con.ChainParams)
		if sc == txscript.ScriptHashTy && bytes.Equal(addrs[0].Hash160()[:],
			contractHash) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain a contract output")
	}

	outScript, err := txscript.PayToAddrScript(con.RedeemAddr)
	if err != nil {
		return err
	}

	txHash := con.EscrowTx.TxHash()
	contractOutPoint := wire.OutPoint{
		Hash:  txHash,
		Index: uint32(contractOut),
		Tree:  0,
	}

	tx := wire.NewMsgTx()
	tx.LockTime = uint32(con.LockTime)
	tx.AddTxIn(wire.NewTxIn(&contractOutPoint, nil))
	tx.AddTxOut(wire.NewTxOut(0, outScript)) // amount set below
	redeemSize := estimateRedeemSerializeSize(con.EscrowScript, tx.TxOut,
		sigScriptAddSize)
	fee := txrules.FeeForSerializeSize(feePerKb, redeemSize)
	tx.TxOut[0].Value = con.EscrowTx.TxOut[contractOut].Value -
		int64(fee)
	if txrules.IsDustOutput(tx.TxOut[0], feePerKb) {
		return fmt.Errorf("redeem output value of %v is dust",
			dcrutil.Amount(tx.TxOut[0].Value))
	}

	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)
	con.RedeemTx = tx
	con.RedeemBytes = buf.Bytes()

	return nil
}

// AddRedeemScript creates a redeem script to complete the escrow script.
func (con *Contract) AddRedeemScript(secrets [][]byte) error {
	var err error

	con.RedeemScript, err = redeemP2SHContract(con.EscrowScript,
		con.RedeemSig, secrets)
	if err != nil {
		return err
	}
	con.RedeemTx.TxIn[0].SignatureScript = con.RedeemScript

	var buf bytes.Buffer
	buf.Grow(con.RedeemTx.SerializeSize())

	con.RedeemTx.Serialize(&buf)
	con.RedeemBytes = buf.Bytes()

	return nil
}

func (con *Contract) VerifyRedeemTx() error {
	contractHash := dcrutil.Hash160(con.EscrowScript)
	contractOut := -1
	for i, out := range con.EscrowTx.TxOut {
		sc, addrs, _, _ := txscript.ExtractPkScriptAddrs(out.Version,
			out.PkScript, con.ChainParams)
		if sc == txscript.ScriptHashTy && bytes.Equal(addrs[0].Hash160()[:],
			contractHash) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain a contract output")
	}

	txHash := con.EscrowTx.TxHash()
	contractOutPoint := wire.OutPoint{
		Hash:  txHash,
		Index: uint32(contractOut),
		Tree:  0,
	}

	e, err := txscript.NewEngine(
		con.EscrowTx.TxOut[contractOutPoint.Index].PkScript,
		con.RedeemTx, 0, verifyFlags, txscript.DefaultScriptVersion,
		txscript.NewSigCache(10))
	if err != nil {
		return err
	}
	if err = e.Execute(); err != nil {
		return err
	}
	return nil
}

// redeemP2SHContract returns the signature script to redeem a contract
// output using the redeemer's signature and secret values. This function
// assumes P2SH and appends the contract as the final data push.
func redeemP2SHContract(contract, sig []byte, secrets [][]byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddData(sig)
	for i, secret := range secrets {
		fmt.Printf("secret %d: %x\n", i, secret)
		b.AddData(secret)
	}
	b.AddInt64(1)
	b.AddData(contract)
	return b.Script()
}

func (con *Contract) ExtractRedeemDataPushes(in uint32) ([][]byte, error) {
	if con.RedeemTx == nil {
		var tx wire.MsgTx
		err := tx.Deserialize(bytes.NewReader(con.RedeemBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize tx: %v",
				err)
		}
		con.RedeemTx = &tx
	}
	data, err := txscript.PushedData(con.RedeemTx.TxIn[in].SignatureScript)
	if err != nil {
		return nil, fmt.Errorf("failed to extract data pushes from "+
			"input %d of a redeeming signature script: %v", in, err)
	}
	return data, nil
}
