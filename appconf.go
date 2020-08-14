package fabric_connector

import (
	"go/build"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
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

func LoadConfigBytesFromFile(filePath string) ([]byte, error) {
	// read test config file into bytes array
	f, err := os.Open(filePath)
	if err != nil {
		return nil, errors.Errorf("Failed to read config file. Error: %s", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, errors.Errorf("Failed to read config file stat. Error: %s", err)
	}
	s := fi.Size()
	cBytes := make([]byte, s)
	n, err := f.Read(cBytes)
	if err != nil {
		return nil, errors.Errorf("Failed to read test config for bytes array testing. Error: %s", err)
	}
	if n == 0 {
		return nil, errors.Errorf("Failed to read test config for bytes array testing. Mock bytes array is empty")
	}
	return cBytes, err
}

type AppConf struct {
	Conf Application `yaml:"application"`
}

type Application struct {
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
