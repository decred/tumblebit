// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This package offers a storage for and basic manupulations with contracts
// used in the TumbleBit protocol.
package contract

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
)

const (
	// This overrides all contract amount values until we support multiple
	// or arbitrary denominations.
	contractValue = dcrutil.AtomsPerCoin // One buck.

	// Add more information when printing out the contract.
	verbosePrintout = true
)

type addressRole int

const (
	ReceiverAddress addressRole = iota
	RedeemAddress
	RefundAddress
	SenderAddress
	MaxAddressRole
)

type addressType int

const (
	PayToEdwardsPubKey addressType = 1 << iota
	PayToPubKey
	PayToPubKeyHash
	PayToSecSchnorrPubKey
	PayToScriptHash
)

var addressName = [...]string{
	ReceiverAddress: "receiver",
	RedeemAddress:   "redeem",
	RefundAddress:   "refund",
	SenderAddress:   "sender",
}

// Contract structure represents the contract associated with a client.
type Contract struct {
	// Generic sender and receiver of funds.
	SenderAddr         dcrutil.Address
	SenderAddrStr      string
	SenderScriptAddr   []byte
	ReceiverAddr       dcrutil.Address
	ReceiverAddrStr    string
	ReceiverScriptAddr []byte

	// Escrow set up by the tumbler or the client.
	EscrowTx        *wire.MsgTx
	EscrowBytes     []byte
	EscrowAddr      dcrutil.Address // P2SH address
	EscrowAddrStr   string
	EscrowPayScript []byte
	EscrowScript    []byte
	EscrowSig       []byte // transaction signature (same for all)
	EscrowHash      []byte // published transaction hash (same for all)

	// Refunding transaction used with an escrow that tumbler sets up.
	RefundTx         *wire.MsgTx
	RefundBytes      []byte
	RefundAddr       dcrutil.Address
	RefundAddrStr    string
	RefundScript     []byte
	RefundScriptAddr []byte
	RefundSig        []byte
	RefundHash       []byte

	// Fulfill the offer transaction and redeem escrowed funds.
	RedeemTx         *wire.MsgTx
	RedeemBytes      []byte
	RedeemAddr       dcrutil.Address
	RedeemAddrStr    string
	RedeemScript     []byte
	RedeemScriptAddr []byte
	RedeemSig        []byte
	RedeemHash       []byte

	Amount      int64
	LockTime    int32
	ChainParams *chaincfg.Params
}

// New creates a new contract template that can be either refunded by
// refundAddr or redeemed by redeemAddr for a specified amount and after
// the specified locktime.
func New(chainParams *chaincfg.Params, amount int64, lockTime int32) (*Contract, error) {
	if amount != contractValue {
		return nil, fmt.Errorf("attempted contract amount: %d", amount)
	}
	c := &Contract{
		Amount:      contractValue,
		ChainParams: chainParams,
		LockTime:    lockTime,
	}
	return c, nil
}

// SetAddress sets an address in the contract according to the role
// specified by the address type. It panics when called with an incorrect
// address type, otherwise address is decoded and verified to be valid in
// the selected network.
func (c *Contract) SetAddress(t addressRole, a, pk string) error {
	if t >= MaxAddressRole {
		panic("unknown address role")
	}

	addr, err := dcrutil.DecodeAddress(pk, c.ChainParams)
	if err != nil {
		return fmt.Errorf("failed to decode %s pubkey: %v",
			addressName[t], err)
	}

	check, err := dcrutil.DecodeAddress(a, c.ChainParams)
	if err != nil {
		return fmt.Errorf("failed to decode %s address: %v",
			addressName[t], err)
	}

	if addr.Address() != check.Address() {
		return errors.New("address and public key don't match")
	}

	switch t {
	case ReceiverAddress:
		// Addresses must have an associated secp256k1 private key and
		// therefore must be P2PK or P2PKH (P2SH is not allowed).
		if !checkAddressType(check, PayToPubKey|PayToPubKeyHash) {
			return fmt.Errorf("address %v is not a secp256k1 P2PK "+
				"or P2PKH", a)
		}
		c.ReceiverAddr = addr
		c.ReceiverAddrStr = a
		c.ReceiverScriptAddr = addr.ScriptAddress()
	case RedeemAddress:
		// Make sure the refund address is P2PKH
		if !checkAddressType(check, PayToPubKeyHash) {
			return fmt.Errorf("address %v is not P2PKH", a)
		}
		c.RedeemAddr = addr
		c.RedeemAddrStr = a
		c.RedeemScriptAddr = addr.ScriptAddress()
	case RefundAddress:
		// Make sure the refund address is P2PKH
		if !checkAddressType(check, PayToPubKeyHash) {
			return fmt.Errorf("address %v is not a secp256k1 P2PKH",
				a)
		}
		c.RefundAddr = addr
		c.RefundAddrStr = a
		c.RefundScriptAddr = addr.ScriptAddress()
	case SenderAddress:
		// Addresses must have an associated secp256k1 private key and
		// therefore must be P2PK or P2PKH (P2SH is not allowed).
		if !checkAddressType(check, PayToPubKey|PayToPubKeyHash) {
			return fmt.Errorf("address %v is not a secp256k1 P2PK "+
				"or P2PKH", a)
		}
		c.SenderAddr = addr
		c.SenderAddrStr = a
		c.SenderScriptAddr = addr.ScriptAddress()
	default:
		return fmt.Errorf("unknown address type %d", t)
	}
	return nil
}

func checkAddressType(addr dcrutil.Address, allowed addressType) bool {
	var found addressType
	switch a := addr.(type) {
	case *dcrutil.AddressEdwardsPubKey:
		found = PayToEdwardsPubKey
	case *dcrutil.AddressSecpPubKey:
		found = PayToPubKey
	case *dcrutil.AddressPubKeyHash:
		if a.DSA() == dcrec.STEcdsaSecp256k1 {
			found = PayToPubKeyHash
		}
	case *dcrutil.AddressSecSchnorrPubKey:
		found = PayToSecSchnorrPubKey
	case *dcrutil.AddressScriptHash:
		found = PayToScriptHash
	default:
		return false
	}
	return found&allowed != 0
}

func (c *Contract) ParseRedeemTransaction(redeemTx *wire.MsgTx) error {
	// TODO
	return errors.New("NOT IMPLEMENTED")
}

func (c *Contract) String() string {
	str := "Contract{ "
	if len(c.EscrowScript) > 0 {
		str += "Escrow{ "
		if len(c.SenderAddrStr) > 0 {
			str += fmt.Sprintf("from=%s ", c.SenderAddrStr)
			if verbosePrintout && len(c.SenderScriptAddr) > 0 {
				str += fmt.Sprintf("sa=%x ", c.SenderScriptAddr)
			}
		}
		if len(c.ReceiverAddrStr) > 0 {
			str += fmt.Sprintf("to=%s ", c.ReceiverAddrStr)
			if verbosePrintout && len(c.ReceiverScriptAddr) > 0 {
				str += fmt.Sprintf("sa=%x ", c.ReceiverScriptAddr)
			}
		}
		if len(c.EscrowHash) > 0 {
			str += fmt.Sprintf("hash=%x ", c.EscrowHash)
		}
		if len(c.EscrowAddrStr) > 0 {
			str += fmt.Sprintf("p2sh=%s ", c.EscrowAddrStr)
		}
		if verbosePrintout && len(c.EscrowBytes) > 0 {
			str += fmt.Sprintf("txlen=%d ", len(c.EscrowBytes))
		}
		if verbosePrintout && len(c.EscrowScript) > 0 {
			str += fmt.Sprintf("scriptlen=%d ", len(c.EscrowScript))
		}
		str += "} "
	}
	if len(c.RefundAddrStr) > 0 {
		str += "Refund{ "
		str += fmt.Sprintf("addr=%s ", c.RefundAddrStr)
		if verbosePrintout && len(c.RefundScriptAddr) > 0 {
			str += fmt.Sprintf("sa=%x ", c.RefundScriptAddr)
		}
		if len(c.RefundHash) > 0 {
			str += fmt.Sprintf("hash=%x ", c.RefundHash)
		}
		if verbosePrintout && len(c.RefundBytes) > 0 {
			str += fmt.Sprintf("txlen=%d ", len(c.RefundBytes))
		}
		if verbosePrintout && len(c.RefundScript) > 0 {
			str += fmt.Sprintf("scriptlen=%d ", len(c.RefundScript))
		}
		str += "} "
	}
	if len(c.RedeemAddrStr) > 0 {
		str += "Redeem{"
		str += fmt.Sprintf("addr=%s ", c.RedeemAddrStr)
		if verbosePrintout && len(c.RedeemScriptAddr) > 0 {
			str += fmt.Sprintf("sa=%x ", c.RedeemScriptAddr)
		}
		if len(c.RedeemHash) > 0 {
			str += fmt.Sprintf("hash=%x ", c.RedeemHash)
		}
		if verbosePrintout && len(c.RedeemBytes) > 0 {
			str += fmt.Sprintf("txlen=%d ", len(c.RedeemBytes))
		}
		if verbosePrintout && len(c.RedeemScript) > 0 {
			str += fmt.Sprintf("scriptlen=%d ", len(c.RedeemScript))
		}
		str += "} "
	}
	if c.Amount > 0 {
		str += fmt.Sprintf("amount=%d ", c.Amount)
	}
	if c.LockTime > 0 {
		str += fmt.Sprintf("locktime=%d ", c.LockTime)
	}
	str += "}"
	return str
}
