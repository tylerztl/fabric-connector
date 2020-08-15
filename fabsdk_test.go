/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabric_connector

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var provider SdkProvider
var (
	testChannelId = "mychannel"
	testCCId      = "mycc"
	testCCVersion = "v0"
	testCCPath    = "chaincode_example02/go"
	testPolicy    = "AND ('Org1MSP.member','Org2MSP.member')"
)

func init() {
	configBytes, err := LoadConfigBytesFromFile("./conf/config.yaml")
	if err != nil {
		panic(err)
	}
	provider, err = NewFabSdkProvider("./conf/app.yaml", configBytes)
	if err != nil {
		panic(err)
	}
}

func TestFabSdkProvider_CreateChannel(t *testing.T) {
	txId, err := provider.CreateChannel(testChannelId)
	assert.NoError(t, err)

	t.Logf("create channel resps: %s", txId)
}

func TestFabSdkProvider_JoinChannel(t *testing.T) {
	err := provider.JoinChannel(testChannelId)
	assert.NoError(t, err)
}

func TestFabSdkProvider_InstallCC(t *testing.T) {
	err := provider.InstallCC(testCCId, testCCVersion, testCCPath)
	assert.NoError(t, err)
}

func TestFabSdkProvider_InstantiateCC(t *testing.T) {
	txId, err := provider.InstantiateCC(testChannelId, testCCId, testCCVersion, testCCPath, testPolicy,
		[][]byte{[]byte("init"), []byte("a"), []byte("100"), []byte("b"), []byte("200")})
	assert.NoError(t, err)

	t.Logf("instantiate chaincode resps: %s", txId)
}

func TestFabSdkProvider_UpgradeCC(t *testing.T) {
	txId, err := provider.UpgradeCC(testChannelId, testCCId, "v1", testCCPath, "OutOf (1, 'Org1MSP.member')",
		[][]byte{[]byte("init"), []byte("a"), []byte("100"), []byte("b"), []byte("200")})
	assert.NoError(t, err)

	t.Logf("upgrade chaincode resps: %s", txId)
}

func TestFabSdkProvider_InvokeCC(t *testing.T) {
	payload, txId, err := provider.InvokeCC(testChannelId, testCCId,
		"move", [][]byte{[]byte("a"), []byte("b"), []byte("10")})
	assert.NoError(t, err)

	t.Logf("invoke chaincode resps, txID: %s, payload: %s", txId, string(payload))
}

func TestFabSdkProvider_QueryCC(t *testing.T) {
	payload, err := provider.QueryCC(testChannelId, testCCId,
		"query", [][]byte{[]byte("a")})
	assert.NoError(t, err)

	t.Logf("query chaincode resps, payload: %s", string(payload))
}

func TestFabSdkProvider_RegisterBlockEvent(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := provider.RegisterBlockEvent(ctx, testChannelId, func(data interface{}) {
			info, _ := data.(*TransactionInfo)
			t.Logf("EventHandler receive data: %v \n", info)
		})
		assert.NoError(t, err)
		wg.Done()
	}()
	go func() {
		_, _, err := provider.InvokeCC(testChannelId, testCCId,
			"move", [][]byte{[]byte("a"), []byte("b"), []byte("10")})
		assert.NoError(t, err)
		wg.Done()
		time.Sleep(time.Second)
		cancel()
	}()
	wg.Wait()
}
