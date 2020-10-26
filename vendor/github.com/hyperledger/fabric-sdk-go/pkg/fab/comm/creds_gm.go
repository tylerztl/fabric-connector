/*
Copyright Zhigui Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"crypto/tls"
	//"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	gcs "github.com/zhigui-projects/gm-crypto/tls"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	"net"
	"strings"
	"unsafe"
)

// gmCreds is the credentials required for authenticating a connection using TLS.
type gmCreds struct {
	config *gcs.Config
	logger *logging.Logger
}

func (c *gmCreds) ClientHandshake(ctx context.Context, addr string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// use local cfg to avoid clobbering ServerName if using multiple endpoints
	var cfg *gcs.Config
	if c.config == nil {
		cfg = &gcs.Config{}
	} else {
		cfg = c.config.Clone()
	}
	if cfg.ServerName == "" {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		cfg.ServerName = addr[:colonPos]
	}

	conn := gcs.Client(rawConn, cfg)
	errChannel := make(chan error, 1)
	go func() {
		errChannel <- conn.Handshake()
	}()
	select {
	case err := <-errChannel:
		if err != nil {
			return nil, nil, err
		}
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return conn, credentials.TLSInfo{State: conn.ConnectionState()}, nil
}

func (c *gmCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn := gcs.Server(rawConn, c.config)
	if err := conn.Handshake(); err != nil {
		if c.logger != nil {
			c.logger.Errorln("remote address",
				conn.RemoteAddr().String()," GM TLS handshake failed with error %s", err)
		}
		return nil, nil, err
	}
	return conn, credentials.TLSInfo{State: conn.ConnectionState()}, nil
}

func (c gmCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
		ServerName:       c.config.ServerName,
	}
}

func (c *gmCreds) Clone() credentials.TransportCredentials {
	return newGMTlS(c.config, c.logger)
}

func (c *gmCreds) OverrideServerName(serverNameOverride string) error {
	c.config.ServerName = serverNameOverride
	return nil
}

// NewTLS uses c to construct a TransportCredentials based on TLS.
func NewTLS(tlsConfig *tls.Config, logger *logging.Logger) credentials.TransportCredentials {
	if config.IsGM() {
		return newGMTlS((*gcs.Config)(unsafe.Pointer(tlsConfig)), logger)
	}

	return credentials.NewTLS(tlsConfig)
}

func newGMTlS(tlsConfig *gcs.Config, logger *logging.Logger) credentials.TransportCredentials {
	tc := &gmCreds{cloneTLSConfig(tlsConfig), logger}
	tc.config.NextProtos = alpnProtoStr
	return tc
}

// cloneTLSConfig returns a shallow clone of the exported
// fields of cfg, ignoring the unexported sync.Once, which
// contains a mutex and must not be copied.
//
// If cfg is nil, a new zero tls.Config is returned.
func cloneTLSConfig(cfg *gcs.Config) *gcs.Config {
	if cfg == nil {
		return &gcs.Config{}
	}

	return cfg.Clone()
}
