/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabric_connector_test

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
)

const RMQ string = "baas"

func TestRsmq(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go producer()
	go consumer()
	wg.Wait()
}


func TestRsmqConsumer(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go consumer()
	wg.Wait()
}

func producer() {
	redis_conn, err := redis.Dial("tcp", "127.0.0.1:6379", redis.DialPassword("cGFzc3cwcmRAcmVkaXMK"))
	if err != nil {
		fmt.Println(err)
		return
	}

	defer redis_conn.Close()

	rand.Seed(time.Now().UnixNano())

	var i = 1

	for {
		_, err = redis_conn.Do("rpush", RMQ, strconv.Itoa(i))
		if err != nil {
			fmt.Println("produce error")
			continue
		}
		fmt.Println("produce element:", i)
		time.Sleep(time.Duration(rand.Intn(10)) * time.Second)
		i++
	}
}

func consumer() {
	redis_conn, err := redis.Dial("tcp", "127.0.0.1:6379", redis.DialPassword("cGFzc3cwcmRAcmVkaXMK"))
	if err != nil {
		fmt.Println(err)
		return
	}

	defer redis_conn.Close()

	rand.Seed(time.Now().UnixNano())

	for {
		ele, err := redis.String(redis_conn.Do("lpop", RMQ))
		if err != nil {
			fmt.Println("no msg.sleep now")
			time.Sleep(time.Duration(rand.Intn(10)) * time.Second)
		} else {
			fmt.Println("cosume element:", ele)
		}
	}
}
