package cmd

import (
	"fmt"
	"path"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	connector "github.com/zhigui-projects/fabric-connector"
)

var (
	channelID         string
	chaincodeName     string
	chaincodeLang     string
	chaincodeCtorJSON string
	configPath        string
	serverPort        string
	redisAddr         string
	redisPassword     string
)

var flags *pflag.FlagSet

var provider connector.SdkProvider

type ChaincodeInput struct {
	Args [][]byte `json:"Args,omitempty"`
}

func InitCmd(cmd *cobra.Command, args []string) {
	configBytes, err := connector.LoadConfigBytesFromFile(path.Join(configPath, "config.yaml"))
	if err != nil {
		panic(err)
	}
	provider, err = connector.NewFabSdkProvider(path.Join(configPath, "app.yaml"), configBytes)
	if err != nil {
		panic(err)
	}
}

func init() {
	resetFlags()
}

// Explicitly define a method to facilitate tests
func resetFlags() {
	flags = &pflag.FlagSet{}

	flags.StringVarP(&channelID, "channelID", "C", "mychannel",
		fmt.Sprint("The channel on which this command should be executed"))

	flags.StringVarP(&chaincodeName, "name", "n", "",
		fmt.Sprint("Name of the chaincode"))

	flags.StringVarP(&chaincodeLang, "language", "l", "go",
		fmt.Sprintf("Language the chaincode is written in"))

	flags.StringVarP(&chaincodeCtorJSON, "ctor", "c", "{}",
		fmt.Sprint("Constructor message for the chaincode in JSON format"))

	flags.StringVarP(&configPath, "path", "p", "./conf",
		fmt.Sprintf("Path to config files"))

	flags.StringVar(&serverPort, "port", "8080", "http server port")

	flags.StringVar(&redisAddr, "redisAddr", "localhost:6379", "rsmq server address")

	flags.StringVar(&redisPassword, "redisPassword", "", "rsmq server password")
}

func attachFlags(cmd *cobra.Command, names []string) {
	cmdFlags := cmd.Flags()
	for _, name := range names {
		if flag := flags.Lookup(name); flag != nil {
			cmdFlags.AddFlag(flag)
		} else {
			panic(fmt.Sprint("Could not find flag  to attach to command", "flag", name, "cmd", cmd.Name()))
		}
	}
}

func checkContractCmdParams(cmd *cobra.Command) error {
	if channelID == "" {
		return errors.New("the required parameter 'channelID' is empty")
	}

	if chaincodeName == "" {
		return errors.Errorf("must provide chaincode name")
	}

	if chaincodeCtorJSON == "{}" {
		return errors.Errorf("must provide chaincode function and args")
	}

	chaincodeLang = strings.ToUpper(chaincodeLang)

	return nil
}
