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
	"bytes"
	"crypto/cipher"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
)

func SM4Encrypt(key, src []byte) ([]byte, error) {
	iv := make([]byte, SmCrypto.Sm4BlockSize())
	ciphertxt, err := sm4Encrypt(key, iv, src)
	if err != nil {
		return nil, err
	}
	return ciphertxt, nil
}

func SM4Decrypt(key, src []byte) ([]byte, error) {
	iv := make([]byte, SmCrypto.Sm4BlockSize())
	plaintext, err := sm4Decrypt(key, iv, src)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

type gmsm4Encryptor struct{}

func (*gmsm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	return SM4Encrypt(k.(*gmsm4PrivateKey).privKey, plaintext)
}

type gmsm4Decryptor struct{}

func (*gmsm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	return SM4Decrypt(k.(*gmsm4PrivateKey).privKey, ciphertext)
}

func sm4Encrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := SmCrypto.NewSm4Cipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData := pkcs5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func sm4Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	block, err := SmCrypto.NewSm4Cipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
