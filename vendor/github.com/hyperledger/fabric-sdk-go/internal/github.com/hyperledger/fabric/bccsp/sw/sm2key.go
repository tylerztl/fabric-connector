/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"crypto/elliptic"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"github.com/zhigui-projects/gm-plugins/primitive"
)

type gmsm2PrivateKey struct {
	privKey *primitive.Sm2PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *gmsm2PrivateKey) Bytes() (raw []byte, err error) {
	return SmCrypto.MarshalSm2PrivateKey(k.privKey, nil)
}

// SKI returns the subject key identifier of this key.
func (k *gmsm2PrivateKey) SKI() (ski []byte) {
	if k.privKey == nil {
		return nil
	}

	//Marshall the public key
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.Sm2PublicKey.X, k.privKey.Sm2PublicKey.Y)

	// Hash it
	hash := SmCrypto.NewSm3()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *gmsm2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *gmsm2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *gmsm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &gmsm2PublicKey{&k.privKey.Sm2PublicKey}, nil
}

func (k *gmsm2PrivateKey) PrivateKey() (interface{}, error) {
	return k.privKey, nil
}

type gmsm2PublicKey struct {
	pubKey *primitive.Sm2PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *gmsm2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = SmCrypto.MarshalSm2PublicKey(k.pubKey)
	if err != nil {
		return nil, errors.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *gmsm2PublicKey) SKI() (ski []byte) {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := SmCrypto.NewSm3()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *gmsm2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *gmsm2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *gmsm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

func (k *gmsm2PublicKey) PrivateKey() (interface{}, error) {
	return nil, errors.New("This is a public key [gmsm2PublicKey]")
}
