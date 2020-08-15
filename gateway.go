/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabric_connector

import (
	"context"
	"math/rand"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type ContractEvent func(*fab.CCEvent)

type GatewayService struct {
	gw       *gateway.Gateway
	networks map[string]*gateway.Network
}

func NewGatewayService(configBytes []byte, user string) (*GatewayService, error) {
	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromRaw(configBytes, "yaml")),
		gateway.WithUser(user),
	)
	if err != nil {
		return nil, err
	}

	return &GatewayService{
		gw:       gw,
		networks: make(map[string]*gateway.Network),
	}, nil
}

func (gs *GatewayService) CallContract(channelID, ccID, function string, args []string) ([]byte, error) {
	// Get the network channel
	network, err := gs.GetNetwork(channelID)
	if err != nil {
		return nil, err
	}

	// Get the smart contract
	contract := network.GetContract(ccID)

	// Submit a transaction in that contract to the ledger
	result, err := contract.SubmitTransaction(function, args...)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (gs *GatewayService) RegisterContractEvent(ctx context.Context, channelID, ccID, eventID string, event ContractEvent) error {
	// Get the network channel
	network, err := gs.GetNetwork(channelID)
	if err != nil {
		return err
	}

	// Get the smart contract
	contract := network.GetContract(ccID)

	reg, notifier, err := contract.RegisterEvent(eventID)
	if err != nil {
		return err
	}

	for {
		select {
		case ccEvent := <-notifier:
			event(ccEvent)
		case <-ctx.Done():
			contract.Unregister(reg)
			return nil
		}
	}
}

func (gs *GatewayService) Close() {
	gs.gw.Close()
}

func (gs *GatewayService) GetNetwork(channelID string) (*gateway.Network, error) {
	if network, ok := gs.networks[channelID]; ok {
		return network, nil
	}

	network, err := gs.gw.GetNetwork(channelID)
	if err != nil {
		return nil, err
	}

	gs.networks[channelID] = network
	return network, nil
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
