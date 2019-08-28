package puzzle

import (
	"bytes"
	"testing"
)

var indexListTest = struct {
	input    []int
	expected []byte
}{
	[]int{
		0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 128, 255, 256, 257, 512, 1024,
		65280, 65281, 65534, 65535},
	[]byte{
		0x00, 0x00, 0x01, 0x00, 0x07, 0x00, 0x08, 0x00,
		0x0f, 0x00, 0x10, 0x00, 0x1f, 0x00, 0x20, 0x00,
		0x3f, 0x00, 0x40, 0x00, 0x80, 0x00, 0xff, 0x00,
		0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x04,
		0x00, 0xff, 0x01, 0xff, 0xfe, 0xff, 0xff, 0xff,
	},
}

func TestIndexListEncodeDecode(t *testing.T) {
	checkEnc, err := EncodeIndexList(indexListTest.input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(checkEnc, indexListTest.expected) {
		t.Logf("received %x\nexpected %x\n", checkEnc, indexListTest.expected)
		t.Fatal("encoding failure")
	}
	checkDec, err := DecodeIndexList(checkEnc)
	if err != nil {
		t.Fatal(err)
	}
	if len(checkDec) != len(indexListTest.input) {
		t.Fatal("bad length")
	}
	for i := range indexListTest.input {
		if checkDec[i] != indexListTest.input[i] {
			t.Logf("received %x\nexpected %x\n", checkDec, indexListTest.input)
			t.Fatal("decoding failure")
		}
	}
}

func TestIndexListEncode(t *testing.T) {
	check, err := EncodeIndexList([]int{})
	if err != nil || len(check) > 0 {
		t.Fatal("failed to encode an empty list")
	}
	_, err = EncodeIndexList([]int{-1})
	if err == nil {
		t.Fatal("didn't fail on negative input")
	}
	_, err = EncodeIndexList([]int{65536})
	if err == nil {
		t.Fatal("didn't fail on out-of-bounds input")
	}
}

func TestIndexListDecode(t *testing.T) {
	check, err := DecodeIndexList([]byte{})
	if err != nil || len(check) > 0 {
		t.Fatal("failed to decode an empty list")
	}
	_, err = DecodeIndexList([]byte{0x00})
	if err == nil {
		t.Fatal("didn't fail on odd number of bytes")
	}
	_, err = DecodeIndexList([]byte{0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("didn't fail on odd number of bytes")
	}
}
