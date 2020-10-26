/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package primitive

type Context interface {
	KeysGenerator
	Sm2Crypto
	Sm3Crypro
	Sm4Crypro
}
