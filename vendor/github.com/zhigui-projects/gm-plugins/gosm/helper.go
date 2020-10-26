/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gosm

import (
	"github.com/zhigui-projects/gm-go/sm2"
	"github.com/zhigui-projects/gm-plugins/primitive"
)

func publicKeyToSm2(k *primitive.Sm2PublicKey) *sm2.PublicKey {
	return &sm2.PublicKey{
		Curve: k.Curve,
		X:     k.X,
		Y:     k.Y,
	}
}

func privateKeyToSm2(k *primitive.Sm2PrivateKey) *sm2.PrivateKey {
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = k.Sm2PublicKey.Curve
	priv.PublicKey.X, priv.PublicKey.Y = k.Sm2PublicKey.X, k.Sm2PublicKey.Y
	priv.D = k.D
	return priv
}

func sm2ToPublicKey(k *sm2.PublicKey) *primitive.Sm2PublicKey {
	return &primitive.Sm2PublicKey{
		Curve: k.Curve,
		X:     k.X,
		Y:     k.Y,
	}
}

func sm2ToPrivateKey(k *sm2.PrivateKey) *primitive.Sm2PrivateKey {
	priv := new(primitive.Sm2PrivateKey)
	priv.Sm2PublicKey.Curve = k.PublicKey.Curve
	priv.Sm2PublicKey.X, priv.Sm2PublicKey.Y = k.PublicKey.X, k.PublicKey.Y
	priv.D = k.D
	return priv
}
