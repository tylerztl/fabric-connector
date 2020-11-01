/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"

	gm_plugins "github.com/zhigui-projects/gm-plugins"
	"github.com/zhigui-projects/gm-plugins/primitive"
)

func WritePrivateKeyToPem(FileName string, key *primitive.Sm2PrivateKey, pwd []byte) (bool, error) {
	var block *pem.Block
	der, err := gm_plugins.GetSmCryptoSuite().MarshalSm2PrivateKey(key, pwd)
	if err != nil {
		return false, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED SM2 PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "SM2 PRIVATE KEY",
			Bytes: der,
		}
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ReadPrivateKeyFromPem(fileName string, pwd []byte) (*primitive.Sm2PrivateKey, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	return gm_plugins.GetSmCryptoSuite().ParsePKCS8PrivateKey(block.Bytes, pwd)
}

func ReadPublicKeyFromPem(fileName string, pwd []byte) (*primitive.Sm2PublicKey, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.Errorf("failed to decode public key")
	}

	return gm_plugins.GetSmCryptoSuite().ParseSm2PublicKey(block.Bytes)
}

func WritePublicKeyToPem(FileName string, key *primitive.Sm2PublicKey, _ []byte) (bool, error) {
	der, err := gm_plugins.GetSmCryptoSuite().MarshalSm2PublicKey(key)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	defer file.Close()
	if err != nil {
		return false, err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}
