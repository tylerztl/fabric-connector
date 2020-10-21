package fabric_connector

import (
	"context"

	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
)

type ChaincodeEvent func(*fab.CCEvent)

type SdkProvider interface {
	ChannelOperator
	ChainCodeAdminOperator
	ChainCodeUserOperator
	EventCallBack
}

type ChannelOperator interface {
	CreateChannel(channelID string) (txID string, err error)
	JoinChannel(channelID string) error
}

type ChainCodeAdminOperator interface {
	InstallChainCode(ccID, ccVersion, ccPath string) error
	InstantiateChainCode(channelID, ccID, ccVersion, ccPath, ccPolicy string, args [][]byte) (txID string, err error)
	UpgradeChainCode(channelID, ccID, ccVersion, ccPath, ccPolicy string, args [][]byte) (txID string, err error)
}

type ChainCodeUserOperator interface {
	InvokeChainCode(channelID, ccID, function string, args [][]byte) (payload []byte, txID string, err error)
	QueryChainCode(channelID, ccID, function string, args [][]byte) (payload []byte, err error)
	QueryTransaction(channelID string, transactionID fab.TransactionID) (*pb.ProcessedTransaction, error)
}

type EventCallBack interface {
	RegisterBlockEvent(ctx context.Context, channelID string, event BlockEventWithTransaction) error
}

type Gateway interface {
	ChainCodeUserOperator
	EventCallBack
	SubmitTransaction(channelID, ccID, function string, args []string) (payload []byte, err error)
	EvaluateTransaction(channelID, ccID, function string, args []string) (payload []byte, err error)
	RegisterChaincodeEvent(ctx context.Context, channelID, ccID, eventID string, event ChaincodeEvent) error
	Close()
}
