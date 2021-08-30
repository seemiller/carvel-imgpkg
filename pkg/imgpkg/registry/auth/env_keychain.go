// Copyright 2020 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"strings"
	"sync"

	regauthn "github.com/google/go-containerregistry/pkg/authn"
	regname "github.com/google/go-containerregistry/pkg/name"
)

var _ regauthn.Keychain = &EnvKeychain{}

type envKeychainInfo struct {
	Hostname      string
	Username      string
	Password      string
	IdentityToken string
	RegistryToken string
}

// EnvKeychain implements an authn.Keychain interface by using credentials provided by imgpkg's auth environment vars
type EnvKeychain struct {
	EnvironFunc func() []string

	infos       []envKeychainInfo
	collectErr  error
	collected   bool
	collectLock sync.Mutex
}

// Resolve looks up the most appropriate credential for the specified target.
func (k *EnvKeychain) Resolve(target regauthn.Resource) (regauthn.Authenticator, error) {
	infos, err := k.collect()
	if err != nil {
		return nil, err
	}

	for _, info := range infos {
		if info.Hostname == target.RegistryStr() {
			return regauthn.FromConfig(regauthn.AuthConfig{
				Username:      info.Username,
				Password:      info.Password,
				IdentityToken: info.IdentityToken,
				RegistryToken: info.RegistryToken,
			}), nil
		}
	}

	return regauthn.Anonymous, nil
}

func (k *EnvKeychain) collect() ([]envKeychainInfo, error) {
	k.collectLock.Lock()
	defer k.collectLock.Unlock()

	if k.collected {
		return append([]envKeychainInfo{}, k.infos...), nil
	}
	if k.collectErr != nil {
		return nil, k.collectErr
	}

	const (
		globalEnvironPrefix = "IMGPKG_REGISTRY_"
		sep                 = "_"
	)

	funcsMap := map[string]func(*envKeychainInfo, string) error{
		"HOSTNAME": func(info *envKeychainInfo, val string) error {
			registry, err := regname.NewRegistry(val, regname.StrictValidation)
			if err != nil {
				return fmt.Errorf("Parsing registry hostname: %s (e.g. gcr.io, index.docker.io)", err)
			}
			info.Hostname = registry.RegistryStr()
			return nil
		},
		"USERNAME": func(info *envKeychainInfo, val string) error {
			info.Username = val
			return nil
		},
		"PASSWORD": func(info *envKeychainInfo, val string) error {
			info.Password = val
			return nil
		},
		"IDENTITY_TOKEN": func(info *envKeychainInfo, val string) error {
			info.IdentityToken = val
			return nil
		},
		"REGISTRY_TOKEN": func(info *envKeychainInfo, val string) error {
			info.RegistryToken = val
			return nil
		},
	}

	defaultInfo := envKeychainInfo{}
	infos := map[string]envKeychainInfo{}

	for _, env := range k.EnvironFunc() {
		pieces := strings.SplitN(env, "=", 2)
		if len(pieces) != 2 {
			continue
		}

		if !strings.HasPrefix(pieces[0], globalEnvironPrefix) {
			continue
		}

		var matched bool

		for key, updateFunc := range funcsMap {
			switch {
			case pieces[0] == globalEnvironPrefix+key:
				matched = true
				err := updateFunc(&defaultInfo, pieces[1])
				if err != nil {
					k.collectErr = err
					return nil, k.collectErr
				}
			case strings.HasPrefix(pieces[0], globalEnvironPrefix+key+sep):
				matched = true
				suffix := strings.TrimPrefix(pieces[0], globalEnvironPrefix+key+sep)
				info := infos[suffix]
				err := updateFunc(&info, pieces[1])
				if err != nil {
					k.collectErr = err
					return nil, k.collectErr
				}
				infos[suffix] = info
			}
		}
		if !matched {
			k.collectErr = fmt.Errorf("Unknown env variable '%s'", pieces[0])
			return nil, k.collectErr
		}
	}

	var result []envKeychainInfo

	if defaultInfo != (envKeychainInfo{}) {
		result = append(result, defaultInfo)
	}
	for _, info := range infos {
		result = append(result, info)
	}

	k.infos = result
	k.collected = true

	return append([]envKeychainInfo{}, k.infos...), nil
}
