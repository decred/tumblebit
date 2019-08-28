// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package puzzle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/blake2s"
)

// EncodeIndexList encodes a slice of integer values that can be represented
// by a uint16 type in a series of 16 bit little endian values.
func EncodeIndexList(indexList []int) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, i := range indexList {
		if i < 0 || i > math.MaxUint16 {
			return nil, fmt.Errorf("index out of bounds: %d", i)
		}
		err := binary.Write(buf, binary.LittleEndian, uint16(i))
		if err != nil {
			return nil, errors.New("failed to build an index set")
		}
	}
	return buf.Bytes(), nil
}

// DecodeIndexList decodes a buffer containing a series of 16 bit little
// endian values into a slice of integers.
func DecodeIndexList(indexList []byte) ([]int, error) {
	if len(indexList)%2 != 0 {
		return nil, fmt.Errorf("bad list length: %d", len(indexList))
	}
	var res []int
	buf := bytes.NewBuffer(indexList)
	for {
		var v uint16
		err := binary.Read(buf, binary.LittleEndian, &v)
		if err == io.EOF {
			return res, nil
		}
		if err != nil {
			return nil, err
		}
		res = append(res, int(v))
	}
}

// HashIndexList produces a salted cryptographic hash value of a binary
// encoded index list.
func HashIndexList(salt []byte, indexList []int) ([]byte, error) {
	buf, err := EncodeIndexList(indexList)
	if err != nil {
		return nil, err
	}
	h, err := blake2s.New256(salt)
	if err != nil {
		return nil, err
	}
	h.Write(buf)
	sum := h.Sum(nil)
	return sum, nil
}
