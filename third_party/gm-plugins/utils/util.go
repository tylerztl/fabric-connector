/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"crypto"
	"github.com/pkg/errors"
	"github.com/zhigui-projects/gm-plugins/primitive"
)

func CheckSm2PrivateKey(key crypto.Signer) (*primitive.Sm2PrivateKey, error) {
	pri, ok := key.(*primitive.Sm2PrivateKey)
	if !ok {
		return nil, errors.Errorf("Private key transfer to SM2 key type failed")
	}
	return pri, nil
}
