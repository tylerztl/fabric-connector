/*
Copyright Zhigui.com Corp. 2020 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"crypto/sha256"
	"math/big"
)

type VrfPayload struct {
	Endorser  []byte
	Data      []byte
	VrfResult []byte
	VrfProof  []byte
	Payload   []byte
}

type VrfEndorsement struct {
	Endorser []byte
	Data     []byte
	Result   []byte
	Proof    []byte
}

type ChaincodeResponsePayload struct {
	Payload         []byte
	VrfEndorsements []*VrfEndorsement
}

func VrfSortition(candidate, threshold int64, value []byte) (bool, *big.Int) {
	h := sha256.Sum256(value)
	i := new(big.Int)
	i.SetBytes(h[:])
	i.Mul(i, big.NewInt(candidate))
	i.Rsh(i, 256)
	return i.Cmp(big.NewInt(threshold)) >= 0, i
}
