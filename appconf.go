package fabric_connector

import (
	"go/build"
	"path"
	"path/filepath"
)

// ChannelConfigPath is the relative path to the generated channel artifacts directory
var ChannelConfigPath = "artifacts/channel"

// CryptoConfigPath is the relative path to the generated crypto config directory
var CryptoConfigPath = "artifacts/channel/crypto-config"

// Project is the Go project name relative to the Go Path
var Project = "fabric-connector"

// goPath returns the current GOPATH. If the system
// has multiple GOPATHs then the first is used.
func goPath() string {
	gpDefault := build.Default.GOPATH
	gps := filepath.SplitList(gpDefault)

	return gps[0]
}

func GetChannelConfigPath(filename string) string {
	return path.Join(goPath(), "src", Project, ChannelConfigPath, filename)
}

func GetDeployPath() string {
	const ccPath = "artifacts/chaincode"
	return path.Join(goPath(), "src", Project, ccPath)
}

type AppConf struct {
	Conf Application `yaml:"application"`
}

type Application struct {
	LogPath      string          `yaml:"logPath"`
	LogLevel     int8            `yaml:"logLevel"`
	OrgInfo      []*OrgInfo      `yaml:"org"`
	OrderderInfo []*OrderderInfo `yaml:"orderer"`
}

type OrgInfo struct {
	Name  string `yaml:"name"`
	Admin string `yaml:"admin"`
	User  string `yaml:"user"`
}

type OrderderInfo struct {
	Name     string `yaml:"name"`
	Admin    string `yaml:"admin"`
	Endpoint string `yaml:"endpoint"`
}
