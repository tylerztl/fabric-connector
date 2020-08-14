## Hyperledger Fabric Connector

### Prerequisites
- Go 1.14+ installation or later

### Getting started
Download fabric images
```
./scripts/bootstrap.sh
```
Start the fabric network
```
/scripts/start_network.sh -m up
```
Clean the fabric network
```
/scripts/start_network.sh -m down
```

Running the test suite
```
go test -test.run TestFabSdkProvider_CreateChannel
go test -test.run TestFabSdkProvider_JoinChannel
go test -test.run TestFabSdkProvider_InstallCC
go test -test.run TestFabSdkProvider_InstantiateCC
go test -test.run TestFabSdkProvider_InvokeCC
go test -test.run TestFabSdkProvider_QueryCC
```
