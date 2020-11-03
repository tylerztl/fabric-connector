/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabric_connector

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type ChaincodeEvent func(*fab.CCEvent)

type GatewayService struct {
	gw       *gateway.Gateway
	networks map[string]*gateway.Network
}

func NewGatewayService(configPath, userId string, mspOpts ...string) (*GatewayService, error) {
	os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
	var identityOpt gateway.IdentityOption
	if len(mspOpts) == 2 {
		userMspPath, mspId := mspOpts[0], mspOpts[1]
		wallet, err := gateway.NewFileSystemWallet("wallet")
		if err != nil {
			log.Print("Failed to create wallet: ", err)
			os.Exit(1)
		}
		if !wallet.Exists(userId) {
			err = populateWallet(userId, userMspPath, mspId, wallet)
			if err != nil {
				log.Print("Failed to put wallet contents: ", err)
				os.Exit(1)
			}
		}
		identityOpt = gateway.WithIdentity(wallet, userId)
	} else {
		identityOpt = gateway.WithUser(userId)
	}

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(configPath)),
		identityOpt,
	)
	if err != nil {
		return nil, err
	}

	return &GatewayService{
		gw:       gw,
		networks: make(map[string]*gateway.Network),
	}, nil
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

// TxID可以通过合约返回值得到
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
	network, err := gs.GetNetwork(channelID)
	if err != nil {
		return err
	}

	reg, notifier, err := network.RegisterBlockEvent()
	if err != nil {
		return err
	}
	defer network.Unregister(reg)

	skipFirst := false
	for {
		select {
		case e, ok := <-notifier:
			if !ok {
				log.Println("unexpected closed channel while waiting for block event")
			}
			if e.Block == nil {
				log.Println("Expecting block in block event but got nil")
			}
			if skipFirst {
				skipFirst = false
			} else {
				go updateBlock(e.Block, event)
			}
		case <-ctx.Done():
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

func populateWallet(userId, mspPath, mspId string, wallet *gateway.Wallet) error {
	keyDir := filepath.Join(mspPath, "keystore")
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return errors.New("keystore folder should have contain one file")
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return err
	}

	certDir := filepath.Join(mspPath, "signcerts")
	certFiles, err := ioutil.ReadDir(certDir)
	if err != nil {
		return err
	}
	if len(certFiles) != 1 {
		return errors.New("signcerts folder should have contain one file")
	}
	certPath := filepath.Join(certDir, certFiles[0].Name())
	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return err
	}

	identity := gateway.NewX509Identity(mspId, string(cert), string(key))

	err = wallet.Put(userId, identity)
	if err != nil {
		return err
	}
	return nil
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
