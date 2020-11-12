/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/go-redis/redis/v7"
	"github.com/spf13/cobra"
	connector "github.com/zhigui-projects/fabric-connector"
	"github.com/zhigui-projects/fabric-connector/leveldb"
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

var redisClient *redis.Client
var lvldb leveldb.Database

func StartServer() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
	})
	defer redisClient.Close()

	pong, err := redisClient.Ping().Result()
	if err != nil {
		panic("ping redis server err: " + err.Error())
	}
	log.Printf("ping redis server succeed with result: %s", pong)

	provider := leveldb.NewProvider()
	lvldb = provider.GetDBHandle("monitor")
	iter := lvldb.GetIterator(nil, nil)
	for iter.Next() {
		log.Printf("retrieve the persistent block monitoring event [%v], recovering", string(iter.Value()))

		info := &RegisterInfo{}
		err := json.Unmarshal(iter.Value(), info)
		if err != nil {
			log.Println("recovery failed, err: ", err)
			continue
		}
		go BlockListener(info)
	}
	iter.Release()
	if iter.Error() != nil {
		panic(err)
	}

	log.Printf("connected to rsmq [%s], start server on listen port: %s", redisAddr, serverPort)

	flag.Parse()
	log.SetFlags(0)
	http.HandleFunc("/monitor/block", registerBlockEvent)
	log.Fatal(http.ListenAndServe(":"+serverPort, nil))
}

type RegisterInfo struct {
	ConsortiumId   string `json:"consortium_id"`
	ChannelId      string `json:"channel_id"`
	OrgDomain      string `json:"org_domain"`
	OrgId          string `json:"org_id"`
	UserId         string `json:"user_id"`         // optional
	ConnectionFile string `json:"connection_file"` // optional
	BlockHeight    uint64 `json:"block_height"`    // optional
}

type RegisterResp struct {
	ChannelId string `json:"channel_id"`
	OrgDomain string `json:"org_domain"`
	Data      string `json:"data"`
}

func registerBlockEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "accept, content-type, authorization")
	w.Header().Set("content-type", "application/json")

	var err error
	var data string
	info := &RegisterInfo{}
	defer func() {
		status := 200
		if err != nil {
			status = 500
			data = err.Error()
		}
		res, _ := json.Marshal(&RegisterResp{
			ChannelId: info.ChannelId,
			OrgDomain: info.OrgDomain,
			Data:      data,
		})

		w.WriteHeader(status)
		w.Write(res)
	}()

	err = json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		return
	}

	orgId := strings.ReplaceAll(info.OrgDomain, ".", "-")
	info.OrgId = orgId

	key := []byte(strings.Join([]string{info.ConsortiumId, info.ChannelId}, "-"))

	v, err := lvldb.Get(key)
	if err == nil && len(v.([]byte)) != 0 {
		err = errors.New(fmt.Sprintf("block monitor event already registered for [%s]-[%s]",
			string(key), string(v.([]byte))))
		return
	}

	log.Printf("receive new monitor block request, body: %v, "+
		"start block event register...", info)

	val, err := json.Marshal(info)
	if err != nil {
		return
	}
	err = lvldb.Put(key, val)
	if err != nil {
		return
	}

	go BlockListener(info)

	data = "monitor request send succeed!"
}

func BlockListener(reg *RegisterInfo) {
	var connectionPath string
	if reg.ConnectionFile != "" {
		connectionPath = reg.ConnectionFile
	} else {
		connectionPath = path.Join("/mnt/fabric/gateway", reg.OrgDomain, reg.ChannelId, "connection.json")
	}

	var fromBlock uint64 = 0
	v, err := lvldb.Get([]byte(strings.Join([]string{reg.ConsortiumId, reg.ChannelId, "height"}, "-")))
	if err == nil {
		fromBlock, err = strconv.ParseUint(string(v.([]byte)), 10, 64)
		if err != nil {
			panic(err)
		}
	}

	if reg.BlockHeight > fromBlock {
		fromBlock = reg.BlockHeight
	}

	sdk := &connector.FabSdkProvider{}
	err = sdk.RegisterBlockEventRequest(context.Background(), reg.ChannelId, reg.OrgId,
		reg.UserId, connectionPath, fromBlock, func(data *connector.BlockData) {
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
				return
			}

			log.Printf("EventHandler receive data: %s", string(payload))

			hash := sha256.New()
			hash.Write(payload)
			digest := hash.Sum(nil)
			hexVal := hex.EncodeToString(digest)
			reply, err := redisClient.HSet("baas:outqueue:Q", hexVal, string(payload)).Result()
			if err != nil {
				log.Printf("produce block: %d, digest: %s to redis error: %v", data.BlockHeight, hexVal, err)
				return
			}
			log.Printf("produce block: %d, digest: %s to redis with reply: %v", data.BlockHeight, hexVal, reply)

			key := []byte(strings.Join([]string{reg.ConsortiumId, reg.ChannelId, "height"}, "-"))
			err = lvldb.Put(key, []byte(strconv.FormatUint(data.BlockHeight, 10)))
			if err != nil {
				log.Printf("update [%s:%d] failed, err: %v", string(key), data.BlockHeight, err)
				return
			}
		})
	if err != nil {
		log.Printf("register block event failed for channel: %s, err: %v", reg.ChannelId, err)
	}
}
