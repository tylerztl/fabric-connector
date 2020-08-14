package fabric_connector

import "context"

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
	InstallCC(ccID, ccVersion, ccPath string) error
	InstantiateCC(channelID, ccID, ccVersion, ccPath, ccPolicy string, args [][]byte) (txID string, err error)
	UpgradeCC(channelID, ccID, ccVersion, ccPath, ccPolicy string, args [][]byte) (txID string, err error)
}

type ChainCodeUserOperator interface {
	InvokeCC(channelID, ccID, function string, args [][]byte) (payload []byte, txID string, err error)
	QueryCC(channelID, ccID, function string, args [][]byte) (payload []byte, err error)
}

type EventCallBack interface {
	RegisterBlockEvent(ctx context.Context, channelID string, callBack CallBackFunc) error
}
