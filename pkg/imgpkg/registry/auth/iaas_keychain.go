// Copyright 2020 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/k14s/imgpkg/pkg/imgpkg/util"
	credentialprovider "github.com/vdemeester/k8s-pkg-credentialprovider"
)

const (
	enableIaasAuthEnvKey = "IMGPKG_ENABLE_IAAS_AUTH"
)

// NewIaasKeychain implements an authn.Keychain interface by using credentials provided by the iaas metadata services
func NewIaasKeychain(ctx context.Context, environFunc func() []string) (authn.Keychain, error) {
	for _, env := range environFunc() {
		pieces := strings.SplitN(env, "=", 2)
		if len(pieces) != 2 {
			continue
		}

		if pieces[0] != enableIaasAuthEnvKey {
			continue
		}

		enableIaasAuth, err := strconv.ParseBool(pieces[1])
		if err != nil {
			return nil, fmt.Errorf("Expected IMGPKG_ENABLE_IAAS_AUTH to contain a boolean value (true, false). Got %s: %v", pieces[1], err)
		}

		if !enableIaasAuth {
			return &keychain{
				keyring: noOpDockerKeyring{},
			}, nil
		}
	}

	var keyring credentialprovider.DockerKeyring
	ok := make(chan struct{})

	go func() {
		keyring = credentialprovider.NewDockerKeyring()
		close(ok)
	}()

	timeout, cancelFunc := context.WithTimeout(ctx, 15*time.Second)
	defer cancelFunc()

	select {
	case <-ok:
		return &keychain{
			keyring: keyring,
		}, nil
	case <-timeout.Done():
		return nil, fmt.Errorf("Timeout occurred trying to enable iaas provider")
	}
}

type lazyProvider struct {
	kc    *keychain
	image string
}

// Authorization implements Authenticator.
func (lp lazyProvider) Authorization() (*authn.AuthConfig, error) {
	//TODO: test this retry logic <- should we have this? not sure...

	var creds []credentialprovider.AuthConfig
	var found bool

	err := util.Retry(func() error {
		creds, found = lp.kc.keyring.Lookup(lp.image)
		if !found || len(creds) < 1 {
			return fmt.Errorf("keychain returned no credentials for %q", lp.image)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	authConfig := creds[0]
	return &authn.AuthConfig{
		Username:      authConfig.Username,
		Password:      authConfig.Password,
		Auth:          authConfig.Auth,
		IdentityToken: authConfig.IdentityToken,
		RegistryToken: authConfig.RegistryToken,
	}, nil
}

type keychain struct {
	keyring credentialprovider.DockerKeyring
}

// Resolve implements authn.Keychain
func (kc *keychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	var image string
	if repo, ok := target.(name.Repository); ok {
		image = repo.String()
	} else {
		// Lookup expects an image reference and we only have a registry.
		image = target.RegistryStr() + "/foo/bar"
	}

	if creds, found := kc.keyring.Lookup(image); !found || len(creds) < 1 {
		return authn.Anonymous, nil
	}
	// TODO(mattmoor): How to support multiple credentials?
	return lazyProvider{
		kc:    kc,
		image: image,
	}, nil
}

type noOpDockerKeyring struct{}

func (n noOpDockerKeyring) Lookup(image string) ([]credentialprovider.AuthConfig, bool) {
	return nil, false
}
