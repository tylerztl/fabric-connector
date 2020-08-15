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

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/stretchr/testify/assert"
)

var gw Gateway

func init() {
	configBytes, err := LoadConfigBytesFromFile("./conf/config.yaml")
	if err != nil {
		panic(err)
	}
	gw, err = NewGatewayService(configBytes, "User1")
	if err != nil {
		panic(err)
	}
}

func TestGatewayService_CallContract(t *testing.T) {
	payload, err := gw.SubmitTransaction(testChannelId, testCCId, "move", []string{"a", "b", "10", testEventID})
	assert.NoError(t, err)
	t.Log(string(payload))

	result, err := gw.EvaluateTransaction(testChannelId, testCCId, "query", []string{"a"})
	assert.NoError(t, err)
	t.Log(string(result))
}

func TestGatewayService_RegisterContractEvent(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := gw.RegisterChaincodeEvent(ctx, testChannelId, testCCId, testEventID, func(e *fab.CCEvent) {
			t.Logf("ChaincodeEvent receive data: %+v, payload:%s \n", e, string(e.Payload))
		})
		assert.NoError(t, err)
		wg.Done()
	}()
	go func() {
		_, err := gw.SubmitTransaction(testChannelId, testCCId, "move", []string{"a", "b", "10", testEventID})
		assert.NoError(t, err)
		wg.Done()
		time.Sleep(time.Second)
		cancel()
	}()
	wg.Wait()
}

func TestGatewayService_InvokeCC(t *testing.T) {
	payload, txId, err := gw.InvokeChainCode(testChannelId, testCCId,
		"move", [][]byte{[]byte("a"), []byte("b"), []byte("10"), []byte(testEventID)})
	assert.NoError(t, err)

	t.Logf("invoke chaincode resps, txID: %s, payload: %s", txId, string(payload))
}

func TestGatewayService_QueryChainCode(t *testing.T) {
	payload, err := gw.QueryChainCode(testChannelId, testCCId,
		"query", [][]byte{[]byte("a")})
	assert.NoError(t, err)

	t.Logf("query chaincode resps, payload: %s", string(payload))
}

func TestGatewayService_QueryTransaction(t *testing.T) {
	_, txId, err := gw.InvokeChainCode(testChannelId, testCCId,
		"move", [][]byte{[]byte("a"), []byte("b"), []byte("10"), []byte(testEventID)})
	assert.NoError(t, err)

	result, err := gw.QueryTransaction(testChannelId, fab.TransactionID(txId))
	assert.NoError(t, err)
	t.Logf("QueryTransaction [%s]: %+v", txId, result)
}

func TestGatewayService_RegisterBlockEvent(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := gw.RegisterBlockEvent(ctx, testChannelId, func(data *TransactionInfo) {
			t.Logf("EventHandler receive data: %+v \n", data)
		})
		assert.NoError(t, err)
		wg.Done()
	}()
	go func() {
		_, err := gw.SubmitTransaction(testChannelId, testCCId, "move", []string{"a", "b", "10", testEventID})
		assert.NoError(t, err)
		wg.Done()
		time.Sleep(time.Second)
		cancel()
	}()
	wg.Wait()
}
