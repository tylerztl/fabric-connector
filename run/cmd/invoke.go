package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var chaincodeInvokeCmd *cobra.Command

const invokeCmdName = "invoke"

func InvokeCmd() *cobra.Command {
	chaincodeInvokeCmd = &cobra.Command{
		Use:       invokeCmdName,
		Short:     "Invoke the specified chaincode.",
		Long:      "Invoke the specified chaincode. It will try to commit the endorsed transaction to the network.",
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
	attachFlags(chaincodeInvokeCmd, flagList)

	return chaincodeInvokeCmd
}

func chaincodeInvokeOrQuery(cmd *cobra.Command, args []string) error {
	if err := checkContractCmdParams(cmd); err != nil {
		return err
	}

	var f map[string][]string
	err := json.Unmarshal([]byte(chaincodeCtorJSON), &f)
	if err != nil {
		return errors.Wrap(err, "chaincode argument error")
	}
	val, ok := f["Args"]
	if !ok {
		return errors.Wrap(err, "chaincode args error")
	}
	var method string
	arguments := make([][]byte, len(val)-1)
	for k, v := range val {
		if k == 0 {
			method = v
		} else {
			arguments[k-1] = []byte(v)
		}
	}

	var payload []byte
	var txID string
	if cmd.Name() == invokeCmdName {
		payload, txID, err = provider.InvokeChainCode(channelID, chaincodeName, method, arguments)
	} else {
		payload, err = provider.QueryChainCode(channelID, chaincodeName, method, arguments)
	}
	if err != nil {
		return err
	}

	fmt.Printf("invoke chaincode resps, txID: %s, payload: %s\n", txID, string(payload))
	return nil
}
