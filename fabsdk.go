package fabric_connector

import (
	"context"
	"fmt"
	"io/ioutil"

	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	contextAPI "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/events/deliverclient/seek"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/cauthdsl"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type OrgInstance struct {
	Config      *OrgInfo
	AdminClient *resmgmt.Client
	MspClient   *mspclient.Client
	Peers       []fab.Peer
}

type OrdererInstance struct {
	Config      *OrderderInfo
	AdminClient *resmgmt.Client
}

type FabSdkProvider struct {
	Sdk      *fabsdk.FabricSDK
	Orgs     []*OrgInstance
	Orderers []*OrdererInstance
}

func loadOrgPeers(org string, ctxProvider contextAPI.ClientProvider) ([]fab.Peer, error) {
	ctx, err := ctxProvider()
	if err != nil {
		return nil, err
	}

	orgPeers, ok := ctx.EndpointConfig().PeersConfig(org)
	if !ok {
		return nil, errors.Errorf("Failed to load org peers for %s", org)
	}
	peers := make([]fab.Peer, len(orgPeers))
	for i, val := range orgPeers {
		if peer, err := ctx.InfraProvider().CreatePeerFromConfig(&fab.NetworkPeer{PeerConfig: val}); err != nil {
			return nil, err
		} else {
			peers[i] = peer
		}
	}
	return peers, nil
}

func NewFabSdkProvider(appConfigPath string, configBytes []byte) (*FabSdkProvider, error) {
	var appConfig AppConf
	yamlFile, err := ioutil.ReadFile(appConfigPath)
	if err != nil {
		panic(fmt.Errorf("yamlFile.Get err[%s]", err))
	}
	if err = yaml.Unmarshal(yamlFile, &appConfig); err != nil {
		return nil, errors.Errorf("yamlFile.Unmarshal err[%s]", err)
	}
	appConf := appConfig.Conf

	configOpt := config.FromRaw(configBytes, "yaml")
	sdk, err := fabsdk.New(configOpt)
	if err != nil {
		return nil, errors.Errorf("Failed to create new SDK: %s", err.Error())
	}

	provider := &FabSdkProvider{
		Sdk:      sdk,
		Orgs:     make([]*OrgInstance, len(appConf.OrgInfo)),
		Orderers: make([]*OrdererInstance, len(appConf.OrderderInfo)),
	}

	for i, org := range appConf.OrgInfo {

		//clientContext allows creation of transactions using the supplied identity as the credential.
		adminContext := sdk.Context(fabsdk.WithUser(org.Admin), fabsdk.WithOrg(org.Name))

		mspClient, err := mspclient.New(sdk.Context(), mspclient.WithOrg(org.Name))
		if err != nil {
			return nil, errors.Errorf("Failed to create mspClient for %s, err: %v", org.Name, err)
		}
		// Resource management client is responsible for managing channels (create/update channel)
		// Supply user that has privileges to create channel (in this case orderer admin)
		adminClient, err := resmgmt.New(adminContext)
		if err != nil {
			return nil, errors.Errorf("Failed to new resource management client: %s", err)
		}

		orgPeers, err := loadOrgPeers(org.Name, adminContext)
		if err != nil {
			return nil, errors.Errorf("Failed to load peers for %s, err: %v", org.Name, err)
		}

		provider.Orgs[i] = &OrgInstance{org, adminClient, mspClient, orgPeers}
	}

	if len(provider.Orgs) == 0 {
		return nil, errors.New("Not provider org config in conf/app.yaml")
	}

	for i, orderer := range appConf.OrderderInfo {
		//clientContext allows creation of transactions using the supplied identity as the credential.
		adminContext := sdk.Context(fabsdk.WithUser(orderer.Admin), fabsdk.WithOrg(orderer.Name))

		// Resource management client is responsible for managing channels (create/update channel)
		// Supply user that has privileges to create channel (in this case orderer admin)
		adminClient, err := resmgmt.New(adminContext)
		if err != nil {
			return nil, errors.Errorf("Failed to new resource management client: %s", err)
		}
		provider.Orderers[i] = &OrdererInstance{orderer, adminClient}
	}
	return provider, nil
}

func (f *FabSdkProvider) CreateChannel(channelID string) (string, error) {
	if len(f.Orderers) == 0 {
		return "", errors.New("not found orderers")
	}

	signingIdentities := make([]msp.SigningIdentity, len(f.Orgs))
	var err error
	for i, org := range f.Orgs {
		signingIdentities[i], err = org.MspClient.GetSigningIdentity(org.Config.Admin)
		if err != nil {
			return "", errors.Errorf("MspClient getSigningIdentity err: %s", err)
		}
	}

	req := resmgmt.SaveChannelRequest{ChannelID: channelID,
		ChannelConfigPath: GetChannelConfigPath(channelID + ".tx"),
		SigningIdentities: signingIdentities}

	txID, err := f.Orderers[0].AdminClient.SaveChannel(req, resmgmt.WithRetry(retry.DefaultResMgmtOpts),
		resmgmt.WithOrdererEndpoint(f.Orderers[0].Config.Endpoint))
	if err != nil {
		return "", errors.Errorf("Failed SaveChannel: %s", err)
	}
	fmt.Printf("Successfully created channel: %s \n", channelID)
	return string(txID.TransactionID), nil
}

func (f *FabSdkProvider) JoinChannel(channelID string) error {
	if len(f.Orderers) == 0 {
		return errors.New("not found orderers")
	}

	for _, orgInstance := range f.Orgs {
		// Org peers join channel
		if err := orgInstance.AdminClient.JoinChannel(channelID, resmgmt.WithRetry(retry.DefaultResMgmtOpts),
			resmgmt.WithOrdererEndpoint(f.Orderers[0].Config.Endpoint)); err != nil {
			return err
		}
		fmt.Printf("%s joined channel: %s successfully\n", orgInstance.Config.Name, channelID)
	}
	return nil
}

func (f *FabSdkProvider) InstallChainCode(ccID, ccVersion, ccPath string) error {
	ccPkg, err := gopackager.NewCCPackage(ccPath, GetDeployPath())
	if err != nil {
		return err
	}
	// Install example cc to org peers
	installCCReq := resmgmt.InstallCCRequest{Name: ccID, Path: ccPath, Version: ccVersion, Package: ccPkg}

	for _, orgInstance := range f.Orgs {
		_, err = orgInstance.AdminClient.InstallCC(installCCReq, resmgmt.WithRetry(retry.DefaultResMgmtOpts))
		if err != nil {
			return err
		}
		fmt.Printf("Successfully install chaincode [%s:%s] to %s peers\n", ccID, ccVersion, orgInstance.Config.Name)
	}
	return err
}

func (f *FabSdkProvider) InstantiateChainCode(channelID, ccID, ccVersion, ccPath, ccPolicy string, args [][]byte) (string, error) {
	policy, err := cauthdsl.FromString(ccPolicy)
	if err != nil {
		return "", errors.Errorf("Failed parse cc policy[%s], err:%v", ccPolicy, err)
	}

	// Org resource manager will instantiate 'example_cc' on channel
	resp, err := f.Orgs[0].AdminClient.InstantiateCC(
		channelID,
		resmgmt.InstantiateCCRequest{Name: ccID, Path: ccPath, Version: ccVersion, Args: args, Policy: policy},
		resmgmt.WithRetry(retry.DefaultResMgmtOpts),
	)
	if err != nil {
		return "", err
	}
	fmt.Printf("Successfully instantiate chaincode  [%s:%s]\n", ccID, ccVersion)
	return string(resp.TransactionID), nil
}

func (f *FabSdkProvider) UpgradeChainCode(channelID, ccID, ccVersion, ccPath, ccPolicy string, args [][]byte) (string, error) {
	policy, err := cauthdsl.FromString(ccPolicy)
	if err != nil {
		return "", errors.Errorf("Failed parse cc policy[%s], err:%v", ccPolicy, err)
	}

	// Org resource manager will instantiate 'example_cc' on channel
	resp, err := f.Orgs[0].AdminClient.UpgradeCC(
		channelID,
		resmgmt.UpgradeCCRequest{Name: ccID, Path: ccPath, Version: ccVersion, Args: args, Policy: policy},
		resmgmt.WithRetry(retry.DefaultResMgmtOpts),
	)
	if err != nil {
		return "", err
	}
	fmt.Printf("Successfully upgrade chaincode  [%s:%s]\n", ccID, ccVersion)
	return string(resp.TransactionID), nil
}

func (f *FabSdkProvider) InvokeChainCode(channelID, ccID, function string, args [][]byte) ([]byte, string, error) {
	//ledger.WithTargets(orgTestPeer0, orgTestPeer1)
	orgInstance := f.Orgs[0]
	//prepare context
	userContext := f.Sdk.ChannelContext(channelID, fabsdk.WithUser(orgInstance.Config.User), fabsdk.WithOrg(orgInstance.Config.Name))
	//get channel client
	chClient, err := channel.New(userContext)
	if err != nil {
		return nil, "", errors.Errorf("Failed to create new channel client:  %s, err: %v", orgInstance.Config.Name, err)
	}
	// Synchronous transaction
	response, err := chClient.Execute(
		channel.Request{
			ChaincodeID: ccID,
			Fcn:         function,
			Args:        args,
		},
		channel.WithRetry(retry.DefaultChannelOpts))
	if err != nil {
		return nil, "", err
	}
	fmt.Printf("Successfully invoke chaincode  ccName[%s] func[%v] txId[%v] payload[%v]\n",
		ccID, function, response.TransactionID, string(response.Payload))
	return response.Payload, string(response.TransactionID), nil
}

func (f *FabSdkProvider) QueryChainCode(channelID, ccID, function string, args [][]byte) ([]byte, error) {
	orgInstance := f.Orgs[0]

	//prepare context
	userContext := f.Sdk.ChannelContext(channelID, fabsdk.WithUser(orgInstance.Config.User), fabsdk.WithOrg(orgInstance.Config.Name))
	//get channel client
	chClient, err := channel.New(userContext)
	if err != nil {
		return nil, errors.Errorf("Failed to create new channel client:  %s", orgInstance.Config.Name)
	}

	response, err := chClient.Query(channel.Request{ChaincodeID: ccID, Fcn: function, Args: args},
		channel.WithRetry(retry.DefaultChannelOpts))
	if err != nil {
		return nil, err
	}

	fmt.Printf("Successfully query chaincode  ccName[%s] func[%v] payload[%v]\n",
		ccID, function, string(response.Payload))
	return response.Payload, nil
}

func (f *FabSdkProvider) QueryTransaction(channelID string, transactionID fab.TransactionID) (*pb.ProcessedTransaction, error) {
	orgInstance := f.Orgs[0]

	//prepare context
	userContext := f.Sdk.ChannelContext(channelID, fabsdk.WithUser(orgInstance.Config.User), fabsdk.WithOrg(orgInstance.Config.Name))
	//get channel client
	ledgerClient, err := ledger.New(userContext)
	if err != nil {
		return nil, errors.Errorf("Failed to create new channel client:  %s", orgInstance.Config.Name)
	}

	return ledgerClient.QueryTransaction(transactionID)
}

func (f *FabSdkProvider) RegisterBlockEvent(ctx context.Context, channelID string, callBack BlockEventWithTransaction) error {
	orgInstance := f.Orgs[0]
	//prepare context
	userContext := f.Sdk.ChannelContext(channelID, fabsdk.WithUser(orgInstance.Config.User), fabsdk.WithOrg(orgInstance.Config.Name))
	// create event client with block events
	eventClient, err := event.New(userContext, event.WithBlockEvents(), event.WithSeekType(seek.Newest))
	if err != nil {
		return errors.Errorf("Failed to create new events client with block events: %s", err)
	}
	if err := registerBlockEvent(ctx, eventClient, callBack, true); err != nil {
		return err
	}
	return nil
}
