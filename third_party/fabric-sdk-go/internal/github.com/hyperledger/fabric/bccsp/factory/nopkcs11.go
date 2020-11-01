// +build !pkcs11

/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"

	"strconv"

	"github.com/pkg/errors"
	gcx "github.com/zhigui-projects/gm-crypto/x509"
)

// FactoryOpts holds configuration information used to initialize factory implementations
type FactoryOpts struct {
	ProviderName string      `mapstructure:"default" json:"default" yaml:"Default"`
	SwOpts       *SwOpts     `mapstructure:"SW,omitempty" json:"SW,omitempty" yaml:"SwOpts"`
	PluginOpts   *PluginOpts `mapstructure:"PLUGIN,omitempty" json:"PLUGIN,omitempty" yaml:"PluginOpts"`
}

// InitFactories must be called before using factory interfaces
// It is acceptable to call with config = nil, in which case
// some defaults will get used
// Error is returned only if defaultBCCSP cannot be found
func InitFactories(config *FactoryOpts) error {
	factoriesInitOnce.Do(func() {
		// Take some precautions on default opts
		if config == nil {
			config = GetDefaultOpts()
		}

		if config.ProviderName == "" {
			config.ProviderName = "SW"
		}

		if config.SwOpts == nil {
			config.SwOpts = GetDefaultOpts().SwOpts
		}

		var algo string
		var err error
		algo, err = CheckGmCrypto(config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed check gm crypto.")
		}
		gcx.InitX509(algo)

		// Initialize factories map
		bccspMap = make(map[string]bccsp.BCCSP)

		// Software-Based BCCSP
		if config.SwOpts != nil {
			f := &SWFactory{}
			err := initBCCSP(f, config)
			if err != nil {
				factoriesInitError = errors.Wrapf(err, "Failed initializing BCCSP.")
			}
		}

		// BCCSP Plugin
		if config.PluginOpts != nil {
			f := &PluginFactory{}
			err := initBCCSP(f, config)
			if err != nil {
				factoriesInitError = errors.Wrapf(err, "Failed initializing PKCS11.BCCSP %s", factoriesInitError)
			}
		}

		var ok bool
		defaultBCCSP, ok = bccspMap[config.ProviderName]
		if !ok {
			factoriesInitError = errors.Errorf("%s\nCould not find default `%s` BCCSP", factoriesInitError, config.ProviderName)
		}
	})

	return factoriesInitError
}

// GetBCCSPFromOpts returns a BCCSP created according to the options passed in input.
func GetBCCSPFromOpts(config *FactoryOpts) (bccsp.BCCSP, error) {
	var f BCCSPFactory
	switch config.ProviderName {
	case "SW":
		f = &SWFactory{}
	case "PLUGIN":
		f = &PluginFactory{}
	default:
		return nil, errors.Errorf("Could not find BCCSP, no '%s' provider", config.ProviderName)
	}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

func GetHashOptFromOpts(config *FactoryOpts) (string, bccsp.HashOpts, error) {
	switch config.ProviderName {
	case "SW":
		if opt, err := bccsp.GetHashOptFromFamily(config.SwOpts.SecLevel, config.SwOpts.HashFamily); err != nil {
			return "", nil, err
		} else {
			return config.SwOpts.HashFamily, opt, nil
		}
	case "PLUGIN":
		secLv := config.PluginOpts.Config["SecLevel"]
		if secLv == nil {
			return "", nil, errors.Errorf("bccsp plugin provider [%s] hash seclevel not set", config.ProviderName)
		}
		secLevel, err := strconv.Atoi(secLv.(string))
		if err != nil {
			return "", nil, err
		}
		hf := config.PluginOpts.Config["HashFamily"]
		if hf == nil {
			return "", nil, errors.Errorf("bccsp plugin provider [%s] hash family not set", config.ProviderName)
		}

		if opt, err := bccsp.GetHashOptFromFamily(secLevel, hf.(string)); err != nil {
			return "", nil, err
		} else {
			return hf.(string), opt, nil
		}
	default:
		return "", nil, errors.Errorf("Could not find HashOpt from opts, no '%s' provider", config.ProviderName)
	}
}

func CheckGmCrypto(config *FactoryOpts) (string, error) {
	switch config.ProviderName {
	case "SW":
		return config.SwOpts.Algorithm, nil
	case "PLUGIN":
		algo := config.PluginOpts.Config["Algorithm"]
		if algo == nil {
			return "", errors.Errorf("bccsp plugin provider [%s] Algorithm not set", config.ProviderName)
		}
		if algo.(string) == bccsp.GMSM2 {
			return algo.(string), nil
		}
		return "", nil
	default:
		return "", errors.Errorf("Could not find Algorithm from opts, no '%s' provider", config.ProviderName)
	}
}
