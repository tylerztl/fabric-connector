## Hyperledger Fabric Connector

### Prerequisites
- Go 1.14+ installation or later

### Testing on Terminal command line
```
go build -o fabric-connector run/main.go
```
```
./fabric-connector chaincode invoke -C mychannel -n mycc -c '{"Args":["move","a","b","10"]}'
```
```
./fabric-connector chaincode query -C mychannel -n mycc -c '{"Args":["query","a"]}'
```
