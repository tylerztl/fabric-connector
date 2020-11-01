/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_plugins

import (
	"sync"

	"github.com/zhigui-projects/gm-plugins/gosm"
	"github.com/zhigui-projects/gm-plugins/primitive"
)

type SmCryptoSuite struct {
	primitive.Sm2Crypto
	primitive.Sm3Crypro
	primitive.Sm4Crypro
	primitive.KeysGenerator
}

var (
	smOnce sync.Once
	scs    *SmCryptoSuite
)

func GetSmCryptoSuite() primitive.Context {
	smOnce.Do(func() {
		scs = &SmCryptoSuite{
			Sm2Crypto:     new(gosm.GoSm2),
			Sm3Crypro:     new(gosm.GoSm3),
			Sm4Crypro:     new(gosm.GoSm4),
			KeysGenerator: new(gosm.KeysDerive),
		}
	})

	return scs
}
