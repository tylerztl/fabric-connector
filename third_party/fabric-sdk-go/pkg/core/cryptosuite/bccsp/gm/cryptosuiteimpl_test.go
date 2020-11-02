package gm

import (
	"bytes"
	"crypto/sha256"
	"github.com/golang/mock/gomock"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/test/mockcore"
	"testing"
)

func TestBadConfig(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockConfig := mockcore.NewMockCryptoSuiteConfig(mockCtrl)
	mockConfig.EXPECT().SecurityProvider().Return("UNKNOWN")
	mockConfig.EXPECT().SecurityProvider().Return("UNKNOWN")

	//Get cryptosuite using config
	_, err := GetSuiteByConfig(mockConfig)
	if err == nil {
		t.Fatal("Unknown security provider should return error")
	}
}

func TestCryptoSuiteByConfigSW(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockConfig := mockcore.NewMockCryptoSuiteConfig(mockCtrl)
	mockConfig.EXPECT().SecurityProvider().Return("sw").AnyTimes()
	mockConfig.EXPECT().SecurityHashAlgorithm().Return("SM3")
	mockConfig.EXPECT().SecurityAlgorithm().Return("SM2")
	mockConfig.EXPECT().SecurityLevel().Return(256)
	mockConfig.EXPECT().KeyStorePath().Return("/tmp/msp")

	//Get cryptosuite using config
	c, err := GetSuiteByConfig(mockConfig)
	if err != nil {
		t.Fatalf("Not supposed to get error, but got: %s", err)
	}

	verifyHashFn(t, c)
}

func TestCryptoSuiteByBadConfigSW(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockConfig := mockcore.NewMockCryptoSuiteConfig(mockCtrl)
	mockConfig.EXPECT().SecurityProvider().Return("sw")
	mockConfig.EXPECT().SecurityHashAlgorithm().Return("SM0")
	mockConfig.EXPECT().SecurityAlgorithm().Return("SM2")
	mockConfig.EXPECT().SecurityLevel().Return(256)
	mockConfig.EXPECT().KeyStorePath().Return("")

	//Get cryptosuite using config
	_, err := GetSuiteByConfig(mockConfig)
	if err == nil {
		t.Fatal("Bad configuration should return error")
	}
}

func TestCryptoSuiteDefaultEphemeral(t *testing.T) {
	c, err := GetSuiteWithDefaultEphemeral()
	if err != nil {
		t.Fatalf("Not supposed to get error, but got: %s", err)
	}
	verifyHashFn(t, c)
}

func verifyHashFn(t *testing.T, c core.CryptoSuite) {
	msg := []byte("Hello")
	e := sha256.Sum256(msg)
	a, err := c.Hash(msg, &bccsp.SHA256Opts{})
	if err != nil {
		t.Fatalf("Not supposed to get error, but got: %s", err)
	}

	if !bytes.Equal(a, e[:]) {
		t.Fatal("Expected SHA 256 hash function")
	}
}

