package main

import (
	"os"

	"github.com/spf13/cobra"
	cmdpkg "github.com/zhigui-projects/fabric-connector/run/cmd"
)

// The main command describes the service and
// defaults to printing the help message.
var mainCmd = &cobra.Command{
	Use:   "fabric-connector",
	Short: "Connect to the Fabric network and interact with it by calling the chaincode",
	Long:  "Connect to the Fabric network and interact with it by calling the chaincode",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		cmdpkg.InitCmd(cmd, args)
	},
}

var chaincodeCmd = &cobra.Command{
	Use:   "chaincode",
	Short: "Operate a chaincode: invoke|query.",
	Long:  "Operate a chaincode: invoke|query.",
}

// Cmd returns the cobra command for Chaincode
func ChaincodeCmd() *cobra.Command {
	chaincodeCmd.AddCommand(cmdpkg.InvokeCmd())
	chaincodeCmd.AddCommand(cmdpkg.QueryCmd())

	return chaincodeCmd
}

func main() {
	mainCmd.AddCommand(cmdpkg.ServerCmd())

	// Define command-line flags that are valid for all commands and
	// subcommands.
	mainCmd.AddCommand(ChaincodeCmd())

	// On failure Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if mainCmd.Execute() != nil {
		os.Exit(1)
	}
}
