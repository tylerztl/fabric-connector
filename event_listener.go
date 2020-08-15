package fabric_connector

import (
	"context"
	"fmt"
	"time"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/pkg/errors"
	"github.com/zhigui-projects/fabric-connector/protoutil"
)

type TransactionInfo struct {
	Status      int32
	BlockNumber uint64
	TxIndex     int
	TxId        string
	ChaincodeId string
	Args        []string
	DateTime    time.Time
}

type BlockEventWithTransaction func(*TransactionInfo)

func registerBlockEvent(ctx context.Context, eventClient *event.Client, callBack BlockEventWithTransaction, skipFirst bool) error {
	reg, eventch, err := eventClient.RegisterBlockEvent()
	if err != nil {
		return errors.Errorf("Error registering for block events: %s", err)
	}
	defer eventClient.Unregister(reg)

	for {
		select {
		case e, ok := <-eventch:
			if !ok {
				fmt.Println("unexpected closed channel while waiting for block event")
			}
			if e.Block == nil {
				fmt.Println("Expecting block in block event but got nil")
			}
			if skipFirst {
				skipFirst = false
			} else {
				go updateBlock(e.Block, callBack)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func updateBlock(block *cb.Block, callBack BlockEventWithTransaction) {
	if block.Header.Number == 0 {
		return
	}

	fmt.Printf("Seek block number:%d \n", block.Header.Number)

	for i, envBytes := range block.Data.Data {
		envelope, err := protoutil.GetEnvelopeFromBlock(envBytes)
		if err != nil {
			fmt.Println("Error GetEnvelopeFromBlock:", err)
			break
		}
		cis, err := protoutil.GetCISFromEnvelopeMsg(envelope)
		if err != nil {
			fmt.Printf("error extracting cis from envelope: %s \n", err)
			continue
		}

		payload, err := protoutil.UnmarshalPayload(envelope.Payload)
		if err != nil {
			fmt.Printf("error extracting payload from block: %s \n", err)
			continue
		}
		channelHeader, _ := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
		txTimestamp := channelHeader.Timestamp
		txTime := time.Unix(txTimestamp.GetSeconds(), int64(txTimestamp.GetNanos()))

		validationCode := int32(block.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER][i])

		var ccId string
		var args []string
		if cis != nil && cis.ChaincodeSpec != nil {
			if cis.ChaincodeSpec.ChaincodeId != nil {
				ccId = cis.ChaincodeSpec.ChaincodeId.Name
			}
			if cis.ChaincodeSpec.Input != nil {
				args = make([]string, len(cis.ChaincodeSpec.Input.Args))
				for k, v := range cis.ChaincodeSpec.Input.Args {
					args[k] = string(v)
				}
			}
		}

		txInfo := &TransactionInfo{
			Status:      validationCode,
			BlockNumber: block.Header.Number,
			TxIndex:     i,
			TxId:        channelHeader.TxId,
			ChaincodeId: ccId,
			Args:        args,
			DateTime:    txTime,
		}
		callBack(txInfo)
	}
}
