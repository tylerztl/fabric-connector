/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabric_connector

import (
	"context"
	"math/rand"
	"unsafe"

	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	contextApi "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/api"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type ChaincodeEvent func(*fab.CCEvent)

type GatewayService struct {
	user      string
	gw        *gateway.Gateway
	networks  map[string]*gateway.Network
	providers map[string]contextApi.ChannelProvider
}

// Gateway is the entry point to a Fabric network
type FabGateway struct {
	sdk        *fabsdk.FabricSDK
	cfg        core.ConfigBackend
	org        string
	mspid      string
	peers      []fab.PeerConfig
	mspfactory api.MSPProviderFactory
}

// A Network object represents the set of peers in a Fabric network (channel).
// Applications should get a Network instance from a Gateway using the GetNetwork method.
type FabNetwork struct {
	name    string
	gateway *Gateway
	client  *channel.Client
	event   *event.Client
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
		gw:        gw,
		user:      user,
		networks:  make(map[string]*gateway.Network),
		providers: make(map[string]contextApi.ChannelProvider),
	}, nil
}

func (gs *GatewayService) InvokeChainCode(channelID, ccID, function string, args [][]byte) ([]byte, string, error) {
	// Get the network channel
	network, err := gs.GetNetwork(channelID)
	if err != nil {
		return nil, "", err
	}
	newNetWork := (*FabNetwork)(unsafe.Pointer(network))

	//client := reflect.ValueOf(network).Elem().FieldByName("client")
	//method := client.MethodByName("Execute")
	//if !method.IsValid() {
	//	return nil, "", errors.New("MethodByName: Execute invalid")
	//}
	//
	//execute, ok := method.Interface().(func(request channel.Request, options ...channel.RequestOption) (channel.Response, error))
	//if !ok {
	//	return nil, "", errors.New("invalid method type: Execute")
	//}

	response, err := newNetWork.client.Execute(
		channel.Request{
			ChaincodeID: ccID,
			Fcn:         function,
			Args:        args,
		},
		channel.WithRetry(retry.DefaultChannelOpts))
	if err != nil {
		return nil, "", err
	}
	return response.Payload, string(response.TransactionID), nil
}

func (gs *GatewayService) QueryChainCode(channelID, ccID, function string, args [][]byte) ([]byte, error) {
	// Get the network channel
	network, err := gs.GetNetwork(channelID)
	if err != nil {
		return nil, err
	}
	newNetWork := (*FabNetwork)(unsafe.Pointer(network))

	response, err := newNetWork.client.Query(channel.Request{ChaincodeID: ccID, Fcn: function, Args: args},
		channel.WithRetry(retry.DefaultChannelOpts))
	if err != nil {
		return nil, err
	}
	return response.Payload, nil
}

func (gs *GatewayService) SubmitTransaction(channelID, ccID, function string, args []string) ([]byte, error) {
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

func (gs *GatewayService) EvaluateTransaction(channelID, ccID, function string, args []string) ([]byte, error) {
	// Get the network channel
	network, err := gs.GetNetwork(channelID)
	if err != nil {
		return nil, err
	}

	// Get the smart contract
	contract := network.GetContract(ccID)

	// Submit a transaction in that contract to the ledger
	result, err := contract.EvaluateTransaction(function, args...)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (gs *GatewayService) QueryTransaction(channelID string, transactionID fab.TransactionID) (*pb.ProcessedTransaction, error) {
	cp, err := gs.GetChannelProvider(channelID)
	if err != nil {
		return nil, err
	}

	ledgerClient, err := ledger.New(cp)
	if err != nil {
		return nil, err
	}

	return ledgerClient.QueryTransaction(transactionID)
}

func (gs *GatewayService) RegisterChaincodeEvent(ctx context.Context, channelID, ccID, eventID string, event ChaincodeEvent) error {
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

func (gs *GatewayService) RegisterBlockEvent(ctx context.Context, channelID string, event BlockEventWithTransaction) error {
	// Get the network channel
	network, err := gs.GetNetwork(channelID)
	if err != nil {
		return err
	}
	newNetWork := (*FabNetwork)(unsafe.Pointer(network))

	if err := registerBlockEvent(ctx, newNetWork.event, event, false); err != nil {
		return err
	}
	return nil
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

func (gs *GatewayService) GetChannelProvider(channelID string) (contextApi.ChannelProvider, error) {
	if cp, ok := gs.providers[channelID]; ok {
		return cp, nil
	}

	gw := (*FabGateway)(unsafe.Pointer(gs.gw))

	channelProvider := gw.sdk.ChannelContext(channelID, fabsdk.WithUser(gs.user), fabsdk.WithOrg(gw.org))
	gs.providers[channelID] = channelProvider
	return channelProvider, nil
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
