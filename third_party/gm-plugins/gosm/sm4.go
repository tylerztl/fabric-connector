/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gosm

import (
	"crypto/cipher"

	"github.com/zhigui-projects/gm-go/sm4"
)

type GoSm4 struct{}

func (gs *GoSm4) NewSm4Cipher(key []byte) (cipher.Block, error) {
	return sm4.NewCipher(key)
}

func (gs *GoSm4) Sm4BlockSize() int {
	return sm4.BlockSize
}
