module github.com/zhigui-projects/fabric-connector

go 1.14

require (
	github.com/Shopify/sarama v1.27.0 // indirect
	github.com/adjust/rmq/v3 v3.0.0
	github.com/fsouza/go-dockerclient v1.6.5 // indirect
	github.com/go-redis/redis/v7 v7.4.0
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.1
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/hashicorp/go-version v1.2.1 // indirect
	github.com/hyperledger/fabric v1.4.8 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20200424173818-327c9e2cf77a // indirect
	github.com/hyperledger/fabric-protos-go v0.0.0-20191121202242-f5500d5e3e85
	github.com/hyperledger/fabric-sdk-go v1.0.0-beta2
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v0.0.2-0.20171109065643-2da4a54c5cee
	github.com/spf13/pflag v1.0.1
	github.com/stretchr/testify v1.6.1
	github.com/sykesm/zap-logfmt v0.0.3 // indirect
	github.com/zhigui-projects/gm-crypto v0.0.0 // indirect
	github.com/zhigui-projects/gm-plugins v0.0.0 // indirect
	github.com/zhigui-projects/http v0.0.0 // indirect
	go.uber.org/zap v1.15.0 // indirect
	golang.org/x/tools v0.0.0-20200813231717-0a73ddcff9b8 // indirect
	gopkg.in/yaml.v2 v2.2.4
)

replace (
	github.com/hyperledger/fabric-sdk-go => ./third_party/fabric-sdk-go
	github.com/zhigui-projects/gm-crypto => ./third_party/gm-crypto
	github.com/zhigui-projects/gm-plugins => ./third_party/gm-plugins
	github.com/zhigui-projects/http => ./third_party/http
)
