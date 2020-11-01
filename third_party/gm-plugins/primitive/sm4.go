/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package primitive

import "crypto/cipher"

type Sm4Crypro interface {
	NewSm4Cipher(key []byte) (cipher.Block, error)
	Sm4BlockSize() int
}
