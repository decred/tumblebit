// Copyright (c) 2017-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// The wallet package implements interaction with a dcrwallet via gRPC.
package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	pb "decred.org/dcrwallet/rpc/walletrpc"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/tumblebit/contract"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Wallet represents an interface to an established RPC connection with
// dcrwallet software and supports tumbler with wallet and blockchain
// services.
type Wallet struct {
	c pb.WalletServiceClient

	chainParams *chaincfg.Params

	passphrase []byte
	account    uint32
}

type Config struct {
	Account          uint32
	AccountName      string
	ChainParams      *chaincfg.Params
	WalletConnection *grpc.ClientConn
	WalletPassword   string
}

// New creates a new wallet object associated with the connection conn
// under chainParams. It also makes sure wallet is running and configured
// for the correct network.
func New(ctx context.Context, cfg *Config) (*Wallet, error) {
	w := &Wallet{
		c:           pb.NewWalletServiceClient(cfg.WalletConnection),
		chainParams: cfg.ChainParams,
		account:     cfg.Account,
		passphrase:  []byte(cfg.WalletPassword),
	}

	_, err := w.c.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return nil, fmt.Errorf("Ping %v", err)
	}
	nr, err := w.c.Network(ctx, &pb.NetworkRequest{})
	if err != nil {
		return nil, fmt.Errorf("Network %v", err)
	}
	if nr.ActiveNetwork != uint32(w.chainParams.Net) {
		return nil, errors.New("network mismatch")
	}

	if len(cfg.AccountName) > 0 {
		err = w.SelectAccount(ctx, cfg.AccountName)
		if err != nil {
			return nil, fmt.Errorf("account %s wasn't found", cfg.AccountName)
		}
	}

	return w, nil
}

// SelectAccount looks up an account by the provided name and selects it
// for future wallet operations.
func (w *Wallet) SelectAccount(ctx context.Context, name string) error {
	ar, err := w.c.Accounts(ctx, &pb.AccountsRequest{})
	if err != nil {
		return fmt.Errorf("Accounts %v", err)
	}
	for _, account := range ar.Accounts {
		if account.AccountName == name {
			w.account = account.AccountNumber
			return nil
		}
	}
	return fmt.Errorf("account %s wasn't found", name)
}

func (w *Wallet) CurrentBlockHeight(ctx context.Context) (uint32, error) {
	bbr, err := w.c.BestBlock(ctx, &pb.BestBlockRequest{})
	if err != nil {
		return 0, fmt.Errorf("Accounts %v", err)
	}
	return bbr.Height, nil
}

func (w *Wallet) ImportEscrowScript(ctx context.Context, con *contract.Contract) error {
	isr, err := w.c.ImportScript(ctx, &pb.ImportScriptRequest{
		Passphrase: w.passphrase,
		Script:     con.EscrowScript,
	})
	if err != nil {
		return fmt.Errorf("ImportScript %v", err)
	}
	con.EscrowAddrStr = isr.P2ShAddress
	return nil
}

// CreateEscrow constructs and signs a pay to script hash transaction that
// transfers funds from the tumbler to the client locked until the specified
// locktime. It also creates an associated refund transaction.
func (w *Wallet) CreateEscrow(ctx context.Context, con *contract.Contract) error {
	var err error

	addr, pkey, err := w.GetExtAddress(ctx)
	if err != nil {
		return err
	}
	err = con.SetAddress(contract.SenderAddress, addr, pkey)
	if err != nil {
		return err
	}

	if err = con.AddEscrowScript(); err != nil {
		return fmt.Errorf("failed to create an escrow script: %v", err)
	}

	if err = w.createEscrowTx(ctx, con); err != nil {
		return fmt.Errorf("failed to create an escrow tx: %v", err)
	}

	if err = w.createRefundTx(ctx, con); err != nil {
		return fmt.Errorf("failed to create a refund tx: %v", err)
	}

	return nil
}

func (w *Wallet) createEscrowTx(ctx context.Context, con *contract.Contract) error {
	ctr, err := w.c.ConstructTransaction(ctx, &pb.ConstructTransactionRequest{
		SourceAccount: w.account,
		NonChangeOutputs: []*pb.ConstructTransactionRequest_Output{{
			Destination: &pb.ConstructTransactionRequest_OutputDestination{
				Script:        con.EscrowPayScript,
				ScriptVersion: 0,
			},
			Amount: con.Amount,
		}},
	})
	if err != nil {
		return fmt.Errorf("ConstructTransaction %v", err)
	}

	str, err := w.c.SignTransaction(ctx, &pb.SignTransactionRequest{
		Passphrase:            w.passphrase,
		SerializedTransaction: ctr.UnsignedTransaction,
	})
	if err != nil {
		return fmt.Errorf("SignTransaction %v", err)
	}
	con.EscrowBytes = str.Transaction

	return nil
}

func (w *Wallet) createRefundTx(ctx context.Context, con *contract.Contract) error {
	addr, pkey, err := w.GetIntAddress(ctx)
	if err != nil {
		return err
	}
	if err = con.SetAddress(contract.RefundAddress, addr, pkey); err != nil {
		return err
	}

	if err = con.BuildRefundTx(); err != nil {
		return fmt.Errorf("failed to create a refund tx: %v", err)
	}

	csr, err := w.c.CreateSignature(ctx, &pb.CreateSignatureRequest{
		Passphrase:            w.passphrase,
		Address:               con.SenderAddrStr,
		SerializedTransaction: con.RefundBytes,
		InputIndex:            0,
		HashType:              pb.CreateSignatureRequest_SIGHASH_ALL,
		PreviousPkScript:      con.EscrowScript,
	})
	if err != nil {
		return fmt.Errorf("CreateSignature %v", err)
	}

	con.RefundSig = csr.Signature

	if err = con.AddRefundScript(); err != nil {
		return fmt.Errorf("failed to add a refund script: %v", err)
	}

	if err = con.VerifyRefundTx(); err != nil {
		return fmt.Errorf("failed to verify refund script: %v", err)
	}

	return nil
}

// CreateRedeem creates a transaction redeeming escrowed funds.
func (w *Wallet) CreateRedeem(ctx context.Context, con *contract.Contract) error {
	addr, pkey, err := w.GetIntAddress(ctx)
	if err != nil {
		return err
	}
	if err = con.SetAddress(contract.RedeemAddress, addr, pkey); err != nil {
		return err
	}

	// 73 + 1 -- DER signature size
	if err = con.BuildRedeemTx(73 + 1); err != nil {
		return fmt.Errorf("failed to create a redeem tx: %v", err)
	}

	if err = w.ImportEscrowScript(ctx, con); err != nil {
		return err
	}

	csr, err := w.c.CreateSignature(ctx, &pb.CreateSignatureRequest{
		Passphrase:            w.passphrase,
		Address:               con.ReceiverAddrStr,
		SerializedTransaction: con.RedeemBytes,
		InputIndex:            0,
		HashType:              pb.CreateSignatureRequest_SIGHASH_ALL,
		PreviousPkScript:      con.EscrowScript,
	})
	if err != nil {
		return fmt.Errorf("CreateSignature %v", err)
	}

	con.RedeemSig = csr.Signature

	return nil
}

// PublishRedeem publishes the redeeming transaction.
func (w *Wallet) PublishRedeem(ctx context.Context, con *contract.Contract, peerSig []byte) error {
	err := con.AddRedeemScript([][]byte{peerSig})
	if err != nil {
		return fmt.Errorf("failed to add a redeem script: %v", err)
	}

	if err := con.VerifyRedeemTx(); err != nil {
		return fmt.Errorf("failed to verify redeem script: %v", err)
	}

	ptr, err := w.c.PublishTransaction(ctx, &pb.PublishTransactionRequest{
		SignedTransaction: con.RedeemBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to publish redeem tx: %v", err)
	}
	con.RedeemHash = ptr.TransactionHash

	return nil
}

// PublishRefund publishes the refund transaction.
func (w *Wallet) PublishRefund(ctx context.Context, con *contract.Contract) error {
	ptr, err := w.c.PublishTransaction(ctx, &pb.PublishTransactionRequest{
		SignedTransaction: con.RefundBytes,
	})
	if err != nil {
		return fmt.Errorf("PublishTransaction %v", err)
	}
	con.RefundHash = ptr.TransactionHash

	return nil
}

// PublishEscrow publishes the escrow transaction.
func (w *Wallet) PublishEscrow(ctx context.Context, con *contract.Contract) error {
	ptr, err := w.c.PublishTransaction(ctx, &pb.PublishTransactionRequest{
		SignedTransaction: con.EscrowBytes,
	})
	if err != nil {
		return fmt.Errorf("PublishTransaction %v", err)
	}
	con.EscrowHash = ptr.TransactionHash

	return nil
}

// SignHashes signs a bundle of transaction hashes and returns a bundle of
// created signatures.
func (w *Wallet) SignHashes(ctx context.Context, con *contract.Contract, txHashes [][]byte) ([][]byte, []byte, error) {
	sthr, err := w.c.SignHashes(ctx, &pb.SignHashesRequest{
		Passphrase: w.passphrase,
		Address:    con.SenderAddrStr,
		Hashes:     txHashes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("SignHashes %v", err)
	}
	return sthr.Signatures, sthr.PublicKey, nil
}

// CreateOffer creates an escrow transaction that releases funds when hash
// preimages are published.
func (w *Wallet) CreateOffer(ctx context.Context, con *contract.Contract, hashes [][]byte) error {
	var err error

	addr, pkey, err := w.GetExtAddress(ctx)
	if err != nil {
		return err
	}
	err = con.SetAddress(contract.SenderAddress, addr, pkey)
	if err != nil {
		return err
	}

	if err = con.AddOfferScript(hashes, txscript.OP_RIPEMD160); err != nil {
		return fmt.Errorf("failed to create an offer script: %v", err)
	}

	if err = w.createEscrowTx(ctx, con); err != nil {
		return fmt.Errorf("failed to create an escrow tx: %v", err)
	}

	if err = w.createRefundTx(ctx, con); err != nil {
		return fmt.Errorf("failed to create a refund tx: %v", err)
	}

	return nil
}

// ValidateOffer retrieves the escrow transaction created by the client
// and makes sure it has been confirmed on the blockchain.
func (w *Wallet) ValidateOffer(ctx context.Context, con *contract.Contract, escrowHash []byte) (bool, error) {
	gtr, err := w.c.GetTransaction(ctx, &pb.GetTransactionRequest{
		TransactionHash: escrowHash,
	})
	if err != nil {
		s, ok := status.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("GetTransaction %v", err)
	}

	// Make sure tx has received enough confirmations.
	if gtr.Confirmations < 2 {
		return false, nil
	}

	var escrowTx wire.MsgTx
	err = escrowTx.Deserialize(bytes.NewReader(gtr.Transaction.Transaction))
	if err != nil {
		return true, fmt.Errorf("could not decode escrow tx: %v", err)
	}

	// TODO: add checks

	if escrowTx.TxOut[0].Value < con.Amount {
		return false, fmt.Errorf("escrowed less than advertised: %d",
			escrowTx.TxOut[0].Value)
	}

	con.EscrowTx = &escrowTx

	return true, nil
}

// PublishSolution builds a fulfilling transaction that reveals preimages
// for hashes contained in the offer tx and thus redeems funds escrowed by
// they payer. It publishes both offer and fulfilling transactions.
func (w *Wallet) PublishSolution(ctx context.Context, con *contract.Contract, secrets [][]byte) error {
	addr, pkey, err := w.GetIntAddress(ctx)
	if err != nil {
		return err
	}
	if err = con.SetAddress(contract.RedeemAddress, addr, pkey); err != nil {
		return err
	}

	// RealPreimageCount * 160 bit long RIPEMD-160 solution keys
	if err = con.BuildRedeemTx(len(secrets) * (1 + 20)); err != nil {
		return fmt.Errorf("failed to create a redeem tx: %v", err)
	}

	csr, err := w.c.CreateSignature(ctx, &pb.CreateSignatureRequest{
		Passphrase:            w.passphrase,
		Address:               con.ReceiverAddrStr,
		SerializedTransaction: con.RedeemBytes,
		InputIndex:            0,
		HashType:              pb.CreateSignatureRequest_SIGHASH_ALL,
		PreviousPkScript:      con.EscrowScript,
	})
	if err != nil {
		return fmt.Errorf("CreateSignature %v", err)
	}

	con.RedeemSig = csr.Signature

	err = con.AddRedeemScript(secrets)
	if err != nil {
		return fmt.Errorf("failed to add a redeem script: %v", err)
	}

	if err = con.VerifyRedeemTx(); err != nil {
		return fmt.Errorf("failed to verify redeem script: %v", err)
	}

	ptr, err := w.c.PublishTransaction(ctx, &pb.PublishTransactionRequest{
		SignedTransaction: con.RedeemBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to publish redeem tx: %v", err)
	}
	con.RedeemHash = ptr.TransactionHash

	return nil
}

// OfferRedeemer looks up the transaction spending the escrow and obtains
// hash preimages used to redeem the contract.
func (w *Wallet) OfferRedeemer(ctx context.Context, con *contract.Contract) (bool, [][]byte, error) {
	sr, err := w.c.Spender(ctx, &pb.SpenderRequest{
		TransactionHash: con.EscrowHash,
		Index:           0,
	})
	if err != nil {
		s, ok := status.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("Spender %v", err)
	}

	if err = con.ParseRedeemTransaction(con.RedeemTx); err != nil {
		return false, nil, fmt.Errorf("failed to parse redeeming tx: %v",
			err)
	}

	gtr, err := w.c.GetTransaction(ctx, &pb.GetTransactionRequest{
		TransactionHash: con.RedeemHash,
	})
	if err != nil {
		s, ok := status.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("GetTransaction %v", err)
	}

	// Make sure tx has received enough confirmations.
	if gtr.Confirmations < 2 {
		return false, nil, nil
	}

	data, err := con.ExtractRedeemDataPushes(sr.InputIndex)
	if err != nil {
		return false, nil, err
	}

	return true, data, nil
}

func (w *Wallet) GetIntAddress(ctx context.Context) (string, string, error) {
	nar, err := w.c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   w.account,
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return "", "", fmt.Errorf("NextAddress %v", err)
	}
	return nar.Address, nar.PublicKey, nil
}

func (w *Wallet) GetExtAddress(ctx context.Context) (string, string, error) {
	nar, err := w.c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   w.account,
		Kind:      pb.NextAddressRequest_BIP0044_EXTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return "", "", fmt.Errorf("NextAddress %v", err)
	}
	return nar.Address, nar.PublicKey, nil
}
