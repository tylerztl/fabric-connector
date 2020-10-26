/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package primitive

import (
	"crypto"
	"crypto/elliptic"
	"io"
	"math/big"
)

type Sm2PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type Sm2PrivateKey struct {
	Sm2PublicKey
	D *big.Int
}

func (s *Sm2PrivateKey) Public() crypto.PublicKey {
	return &s.Sm2PublicKey
}

func (s *Sm2PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	panic("Do not invoke me! Please replace for Sm2Crypto.Sign.")
}

type KeysGenerator interface {
	GenPrivateKey() (*Sm2PrivateKey, error)
	PublicKey(k *Sm2PrivateKey) *Sm2PublicKey
	ParsePKCS8UnecryptedPrivateKey(der []byte) (*Sm2PrivateKey, error)
	ParsePKCS8PrivateKey(der, pwd []byte) (*Sm2PrivateKey, error)
	MarshalSm2PrivateKey(k *Sm2PrivateKey, pwd []byte) ([]byte, error)
	ParseSm2PublicKey(der []byte) (*Sm2PublicKey, error)
	MarshalSm2PublicKey(k *Sm2PublicKey) ([]byte, error)
}
