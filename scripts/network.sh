#!/bin/bash
#
# Copyright Ziggurat Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

cd artifacts/network

# Print the usage message
function printHelp () {
  echo "Usage: "
  echo "      network.sh up|down|restart"
  echo "      - 'up' - bring up the network with docker-compose up"
  echo "      - 'down' - clear the network with docker-compose down"
  echo "      - 'restart' - restart the network"
}


function dkcl(){
        CONTAINER_IDS=$(docker ps -aq)
	echo
        if [ -z "$CONTAINER_IDS" -o "$CONTAINER_IDS" = " " ]; then
                echo "========== No containers available for deletion =========="
        else
                docker rm -f $CONTAINER_IDS
        fi
	echo
}

function dkrm(){
        DOCKER_IMAGE_IDS=$(docker images | grep "dev\|none\|test-vp\|peer[0-9]-" | awk '{print $3}')
	echo
        if [ -z "$DOCKER_IMAGE_IDS" -o "$DOCKER_IMAGE_IDS" = " " ]; then
		echo "========== No images available for deletion ==========="
        else
                docker rmi -f $DOCKER_IMAGE_IDS
        fi
	echo
}

function networkUp() {
	echo Start the network
	docker-compose up -d
	echo

	# now run the end to end script
    docker exec cli scripts/script.sh
    if [ $? -ne 0 ]; then
        echo "ERROR !!!! Test failed"
        exit 1
    fi
}

function networkDown() {
    echo teardown the network and clean the containers and intermediate images
	docker-compose down --volumes --remove-orphans
	if [ "$MODE" != "restart" ]; then
	   dkcl
	   dkrm
	fi
}

function networkRestart() {
    networkDown
    networkUp
	echo
}

MODE=$1
#Create the network using docker compose
if [ "${MODE}" == "up" ]; then
  networkUp
  elif [ "${MODE}" == "down" ]; then ## Clear the network
  networkDown
  elif [ "${MODE}" == "restart" ]; then ## Restart the network
  networkRestart
else
  printHelp
  exit 1
fi
