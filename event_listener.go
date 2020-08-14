package fabric_connector

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/pkg/errors"
	"github.com/zhigui-projects/fabric-connector/protoutil"
)

type BlockInfo struct {
	Number    uint64    `json:"number"`
	TxCount   int       `json:"tx_count"`
	BlockHash string    `json:"block_hash"`
	DateTime  time.Time `json:"datetime"`
}

type TransactionInfo struct {
	Status   int       `json:"status"`
	TxId     string    `json:"tx_id"`
	DateTime time.Time `json:"datetime"`
}

type CallBackFunc func(interface{})

func registerBlockEvent(ctx context.Context, eventClient *event.Client, callBack CallBackFunc) error {
	reg, eventch, err := eventClient.RegisterBlockEvent()
	if err != nil {
		return errors.Errorf("Error registering for block events: %s", err)
	}
	defer eventClient.Unregister(reg)
	flag := true
	for {
		select {
		case e, ok := <-eventch:
			if !ok {
				fmt.Println("unexpected closed channel while waiting for block event")
			}
			if e.Block == nil {
				fmt.Println("Expecting block in block event but got nil")
			}
			if flag {
				flag = false
			} else {
				go updateBlock(e.Block, callBack)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func updateBlock(block *cb.Block, callBack CallBackFunc) {
	if block.Header.Number == 0 {
		return
	}

	txLen := len(block.Data.Data)
	var txTime time.Time
	for i, envBytes := range block.Data.Data {
		envelope, err := protoutil.GetEnvelopeFromBlock(envBytes)
		if err != nil {
			fmt.Println("Error GetEnvelopeFromBlock:", err)
			break
		}
		payload, err := protoutil.UnmarshalPayload(envelope.Payload)
		if err != nil {
			fmt.Printf("error extracting payload from block: %s \n", err)
			continue
		}
		channelHeader, _ := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
		txTimestamp := channelHeader.Timestamp
		txTime = time.Unix(txTimestamp.GetSeconds(), int64(txTimestamp.GetNanos()))

		validationCode := int(block.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER][i])

		fmt.Printf("Seek block number:%d \n", block.Header.Number)

		txInfo := &TransactionInfo{
			Status:   validationCode,
			TxId:     channelHeader.TxId,
			DateTime: txTime,
		}
		callBack(txInfo)
	}

	_ = &BlockInfo{
		Number:    block.Header.Number,
		TxCount:   txLen,
		BlockHash: hex.EncodeToString(block.Header.DataHash),
		DateTime:  txTime,
	}
}
