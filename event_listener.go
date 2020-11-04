package fabric_connector

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/pkg/errors"
	"github.com/zhigui-projects/fabric-connector/protoutil"
)

type BlockData struct {
	BlockHeight  uint64    `json:"blockHeight"`
	PreviousHash string    `json:"previousHash"`
	DataHash     string    `json:"dataHash"`
	TimeStamp    string    `json:"timestamp"`
	TxList       []*TxData `json:"txList"`
}

type TxData struct {
	Id             string `json:"id"`
	ChannelId      string `json:"channel_id"`
	TimeStamp      string `json:"timestamp"`
	ValidationCode int32  `json:"validationCode"`
	ChaincodeType  int32  `json:"chaincode_type"`
	ChaincodeName  string `json:"chaincode_name"`
	ChainCodeInput string `json:"chain_code_input"`
	Endorser       string `json:"endorser"`
	EndorserId     string `json:"endorserId"`
}

type BlockEventWithTransaction func(*BlockData)

func registerBlockEvent(ctx context.Context, channelID string, eventClient *event.Client, callBack BlockEventWithTransaction, skipFirst bool) error {
	reg, eventch, err := eventClient.RegisterBlockEvent()
	if err != nil {
		return errors.Errorf("Error registering for block events: %s", err)
	}
	defer eventClient.Unregister(reg)

	fmt.Printf("register block event succeed for %s\n", channelID)

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

	txList := make([]*TxData, 0)
	for i, envBytes := range block.Data.Data {
		envelope, err := protoutil.GetEnvelopeFromBlock(envBytes)
		if err != nil {
			fmt.Println("Error GetEnvelopeFromBlock:", err)
			break
		}

		cis, cap, _, err := protoutil.GetActionFromEnvelopeMsg(envelope)
		//cis, err := protoutil.GetCISFromEnvelopeMsg(envelope)
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

		tx := &TxData{
			Id:             channelHeader.TxId,
			ChannelId:      channelHeader.ChannelId,
			TimeStamp:      txTime.String(),
			ValidationCode: validationCode,
			ChaincodeType:  int32(cis.ChaincodeSpec.Type),
			ChaincodeName:  ccId,
			ChainCodeInput: strings.Join(args, ","),
		}
		if len(cap.Action.Endorsements) > 0 {
			si, err := protoutil.Deserialize(cap.Action.Endorsements[0].Endorser)
			if err == nil {
				tx.Endorser = si.Mspid
				tx.EndorserId = string(si.IdBytes)
			}
		}

		txList = append(txList, tx)
	}

	resBlock := &BlockData{
		BlockHeight:  block.Header.Number,
		PreviousHash: hex.EncodeToString(block.Header.PreviousHash),
		DataHash:     hex.EncodeToString(block.Header.DataHash),
		TxList:       txList,
	}
	if len(txList) > 0 {
		resBlock.TimeStamp = txList[0].TimeStamp
	}

	callBack(resBlock)
}
