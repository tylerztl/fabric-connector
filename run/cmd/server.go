/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"strconv"

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

			go BlockListener(consortiumID, channelID)

			StartServer()
		},
	}

	flagList := []string{
		"channelID",
		"port",
		"redisAddr",
		"redisPassword",
		"path",
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

	flag.Parse()
	log.SetFlags(0)
	http.HandleFunc("/block", block)
	log.Fatal(http.ListenAndServe(":"+serverPort, nil))
}

func block(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
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
	var pageId, size int
	pageId, err = strconv.Atoi(r.FormValue("id"))
	if err != nil {
		return
	}
	size, err = strconv.Atoi(r.FormValue("size"))
	if err != nil {
		return
	}
	if pageId < 1 || size < 1 {
		err = errors.New("invalid pageId")
		return
	}
	// TODO
}

func BlockListener(consortiumId, channelId string) {
	err := provider.RegisterBlockEvent(context.Background(), channelId, func(data *connector.BlockData) {
		payload, err := json.Marshal(&RsmqData{
			Action: "monitor_block",
			Block:  data,
			Extra: &ExtraData{
				ConsortiumId: consortiumId,
				ChannelName:  channelId,
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
		log.Print("register block event failed for channel: ", channelId)
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
