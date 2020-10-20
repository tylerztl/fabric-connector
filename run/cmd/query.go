package cmd

import (
	"github.com/spf13/cobra"
)

var chaincodeQueryCmd *cobra.Command

const queryCmdName = "query"

func QueryCmd() *cobra.Command {
	chaincodeQueryCmd = &cobra.Command{
		Use:       queryCmdName,
		Short:     "Query the specified chaincode.",
		Long:      "Query the specified chaincode.",
		ValidArgs: []string{"1"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return chaincodeInvokeOrQuery(cmd, args)
		},
	}
	flagList := []string{
		"channelID",
		"name",
		"language",
		"ctor",
		"path",
	}
	attachFlags(chaincodeQueryCmd, flagList)

	return chaincodeQueryCmd
}
