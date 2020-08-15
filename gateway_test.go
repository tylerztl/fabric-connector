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
var eventID = RandStringBytes(16)

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
	payload, err := gw.CallContract(testChannelId, testCCId, "move", []string{"a", "b", "10", eventID})
	assert.NoError(t, err)
	t.Log(string(payload))

	result, err := gw.CallContract(testChannelId, testCCId, "query", []string{"a"})
	assert.NoError(t, err)
	t.Log(string(result))
}

func TestGatewayService_RegisterContractEvent(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := gw.RegisterContractEvent(ctx, testChannelId, testCCId, eventID, func(e *fab.CCEvent) {
			t.Logf("ContractEvent receive data: %+v, payload:%s \n", e, string(e.Payload))
		})
		assert.NoError(t, err)
		wg.Done()
	}()
	go func() {
		_, err := gw.CallContract(testChannelId, testCCId, "move", []string{"a", "b", "10", eventID})
		assert.NoError(t, err)
		wg.Done()
		time.Sleep(time.Second)
		cancel()
	}()
	wg.Wait()
}
