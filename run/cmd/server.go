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
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/go-redis/redis"
	"github.com/grafana/go-rsmq"
	"github.com/spf13/cobra"
	connector "github.com/zhigui-projects/fabric-connector"
	"github.com/zhigui-projects/fabric-connector/leveldb"
)

const RegisterSuffix = "register"
const HeightSuffix = "height"

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

var smq *rsmq.RedisSMQ
var lvldb leveldb.Database
var eventsHub map[string]map[string]context.CancelFunc

func StartServer() {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
	})
	defer redisClient.Close()

	pong, err := redisClient.Ping().Result()
	if err != nil {
		panic("ping redis server err: " + err.Error())
	}
	log.Printf("ping redis server succeed with result: %s", pong)

	eventsHub = make(map[string]map[string]context.CancelFunc)

	smq = rsmq.NewRedisSMQ(redisClient, "baas")

	provider := leveldb.NewProvider()
	lvldb = provider.GetDBHandle("monitor")
	iter := lvldb.GetIterator(nil, nil)
	for iter.Next() {
		if !strings.HasSuffix(string(iter.Key()), RegisterSuffix) {
			continue
		}

		log.Printf("retrieve the persistent block monitoring event [%v], recovering", string(iter.Value()))

		info := &RegisterInfo{}
		err := json.Unmarshal(iter.Value(), info)
		if err != nil {
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
	http.HandleFunc("/monitor/unregister", unregisterBlockEvent)
	log.Fatal(http.ListenAndServe(":"+serverPort, nil))
}

type RegisterInfo struct {
	ConsortiumId   string `json:"consortium_id"`
	ChannelId      string `json:"channel_id"`
	OrgDomain      string `json:"org_domain"`
	OrgId          string `json:"org_id"`
	UserId         string `json:"user_id"`         // optional
	ConnectionFile string `json:"connection_file"` // optional
	BlockHeight    int64  `json:"block_height"`    // optional
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
	info := &RegisterInfo{
		BlockHeight: -1,
	}
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

	key := []byte(strings.Join([]string{info.ConsortiumId, info.ChannelId, RegisterSuffix}, "-"))

	v, err := lvldb.Get(key)
	if err == nil && len(v.([]byte)) != 0 {
		err = errors.New(fmt.Sprintf("block monitor event already registered for [%s]-[%s]",
			string(key), string(v.([]byte))))
		return
	}

	log.Printf("receive new monitor block request, body: %+v, "+
		"start block event register...", info)

	go BlockListener(info)

	data = "monitor request send succeed!"
}

func unregisterBlockEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "accept, content-type, authorization")
	w.Header().Set("content-type", "application/json")

	consortiumId := r.FormValue("consortium_id")
	if consortiumId == "" {
		w.WriteHeader(500)
		w.Write([]byte("invalid consortium_id params because of empty"))
		return
	}

	if _, ok := eventsHub[consortiumId]; !ok {
		w.WriteHeader(500)
		w.Write([]byte("invalid consortium_id params because of not exist"))
		return
	}
	for _, cancel := range eventsHub[consortiumId] {
		cancel()
	}

	iter := lvldb.GetIterator(nil, nil)
	for iter.Next() {
		if !strings.HasPrefix(string(iter.Key()), consortiumId+"-") {
			continue
		}
		lvldb.Delete(iter.Key())
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
	} else {
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("unregister block event succeed for consortiumId: %s", consortiumId)))
	}
}

func BlockListener(reg *RegisterInfo) {
	var connectionPath string
	if reg.ConnectionFile != "" {
		connectionPath = reg.ConnectionFile
	} else {
		connectionPath = path.Join("/mnt/fabric/gateway", reg.OrgDomain, reg.ChannelId, "connection.json")
	}

	var fromBlock int64 = -1
	v, err := lvldb.Get([]byte(strings.Join([]string{reg.ConsortiumId, reg.ChannelId, HeightSuffix}, "-")))
	if err == nil {
		fromBlock, _ = strconv.ParseInt(string(v.([]byte)), 10, 64)
	}
	if reg.BlockHeight > fromBlock {
		fromBlock = reg.BlockHeight
	}

	ctx, cancel := context.WithCancel(context.Background())
	sdk := &connector.FabSdkProvider{}
	err = sdk.RegisterBlockEventRequest(ctx, reg.ChannelId, reg.OrgId,
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

			reply, err := smq.SendMessage("outqueue", string(payload))
			if err != nil {
				log.Printf("produce block: %d to redis error: %v", data.BlockHeight, err)
				return
			}
			log.Printf("produce block: %d to redis with reply: %v", data.BlockHeight, reply)

			key := []byte(strings.Join([]string{reg.ConsortiumId, reg.ChannelId, "height"}, "-"))
			err = lvldb.Put(key, []byte(strconv.FormatUint(data.BlockHeight, 10)))
			if err != nil {
				log.Printf("update [%s:%d] failed, err: %v", string(key), data.BlockHeight, err)
				return
			}
		})
	if err != nil {
		log.Printf("register block event failed for channel: %s, err: %v", reg.ChannelId, err)
	} else {
		if channels, ok := eventsHub[reg.ConsortiumId]; ok {
			if v, ok := channels[reg.ChannelId]; ok {
				v()
			}
			eventsHub[reg.ConsortiumId][reg.ChannelId] = cancel
		} else {
			channels = make(map[string]context.CancelFunc)
			channels[reg.ChannelId] = cancel
			eventsHub[reg.ConsortiumId] = channels
		}

		val, _ := json.Marshal(reg)
		key := []byte(strings.Join([]string{reg.ConsortiumId, reg.ChannelId, RegisterSuffix}, "-"))
		lvldb.Put(key, val)
	}
}
