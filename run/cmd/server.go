/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"path"

	"github.com/adjust/rmq/v3"
	"github.com/go-redis/redis/v7"
	"github.com/spf13/cobra"
	connector "github.com/zhigui-projects/fabric-connector"
)

type RsmqData struct {
	Action string               `json:"action"`
	Block  *connector.BlockData `json:"block"`
	Extra  *ExtraData           `json:"extra"`
}

type ExtraData struct {
	ConsortiumId string `json:"consortium_id"`
	ChannelName  string `json:"channel_name"`
}

func ServerCmd() *cobra.Command {
	serverCmd := &cobra.Command{
		Use:   "start",
		Short: "Run the fabric-connector http server",
		Run: func(cmd *cobra.Command, args []string) {
			defer func() {
				if err := recover(); err != nil {
					log.Print("Recover error: ", err)
				}
			}()

			StartServer()
		},
	}

	flagList := []string{
		"port",
		"redisAddr",
		"redisPassword",
	}
	attachFlags(serverCmd, flagList)

	return serverCmd
}

var taskQueue rmq.Queue

func StartServer() {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
	})

	errChan := make(chan error, 10)
	go logErrors(errChan)

	connection, err := rmq.OpenConnectionWithRedisClient("baas rsmq server", redisClient, errChan)
	if err != nil {
		panic(err)
	}
	taskQueue, err = connection.OpenQueue("baas")
	if err != nil {
		panic(err)
	}

	log.Printf("start server on listen port: %s", serverPort)

	flag.Parse()
	log.SetFlags(0)
	http.HandleFunc("/monitor/block", registerBlockEvent)
	log.Fatal(http.ListenAndServe(":"+serverPort, nil))
}

type RegisterInfo struct {
	ConsortiumId   string `json:"consortium_id"`
	ChannelId      string `json:"channel_id"`
	OrgId          string `json:"org_id"`
	UserId         string `json:"user_id"`
	ConnectionFile string `json:"connection_file"`
}

func registerBlockEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "accept, content-type, authorization")
	w.Header().Set("content-type", "application/json")

	var err error
	var datas []byte
	defer func() {
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		} else {
			w.WriteHeader(200)
			w.Write(datas)
		}
	}()

	info := &RegisterInfo{}
	err = json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		return
	}

	log.Printf("receive new monitor block request, body: %v, "+
		"start block event register...", info)

	go BlockListener(info)

	datas = []byte("monitor request send succeed!")
}

func BlockListener(reg *RegisterInfo) {
	var connectionPath string
	if reg.ConnectionFile != "" {
		connectionPath = reg.ConnectionFile
	} else {
		connectionPath = path.Join(channelID, reg.OrgId, "connection.json")
	}

	sdk := &connector.FabSdkProvider{}
	err := sdk.RegisterBlockEventRequest(context.Background(), reg.ChannelId, reg.OrgId,
		reg.UserId, connectionPath, func(data *connector.BlockData) {
			payload, err := json.Marshal(&RsmqData{
				Action: "monitor_block",
				Block:  data,
				Extra: &ExtraData{
					ConsortiumId: reg.ConsortiumId,
					ChannelName:  reg.ChannelId,
				},
			})
			if err != nil {
				log.Printf("block marshal failed, err: %v", err)
			}

			log.Printf("EventHandler receive data: %s", string(payload))
			err = taskQueue.Publish(string(payload))
			if err != nil {
				log.Printf("block %v send to rsmq failed, err: %v", data.BlockHeight, err)
			}
		})
	if err != nil {
		log.Printf("register block event failed for channel: %s, err: %v", reg.ChannelId, err)
	}
}

func logErrors(errChan <-chan error) {
	for err := range errChan {
		switch err := err.(type) {
		case *rmq.HeartbeatError:
			if err.Count == rmq.HeartbeatErrorLimit {
				log.Print("heartbeat error (limit): ", err)
			} else {
				log.Print("heartbeat error: ", err)
			}
		case *rmq.ConsumeError:
			log.Print("consume error: ", err)
		case *rmq.DeliveryError:
			log.Print("delivery error: ", err.Delivery, err)
		default:
			log.Print("other error: ", err)
		}
	}
}
