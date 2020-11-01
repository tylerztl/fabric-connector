/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package primitive

import "hash"

type Sm3Crypro interface {
	NewSm3() hash.Hash
}
