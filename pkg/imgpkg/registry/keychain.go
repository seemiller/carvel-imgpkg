// Copyright 2020 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0
package registry

import (
	"context"
	"time"

	regauthn "github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/k14s/imgpkg/pkg/imgpkg/registry/auth"
)

// Keychain implements an authn.Keychain interface by composing multiple keychains.
// It enforces an order, where the keychains that contain credentials for a specific target take precedence over
// keychains that contain credentials for 'any' target. i.e. env keychain takes precedence over the custom keychain.
// Since env keychain contains credentials per HOSTNAME, and custom keychain doesn't.
func Keychain(keychainOpts auth.KeychainOpts, environFunc func() []string) regauthn.Keychain {
	var k8sKeychain regauthn.Keychain
	var err error

	var ok = make(chan struct{})

	go func() {
		k8sKeychain, err = k8schain.NewFromPullSecrets(context.Background(), nil)
		if err != nil {
			panic(err.Error())
		}
		close(ok)
	}()

	timeout := time.After(15 * time.Second)
	select {
	case <-ok:
		return regauthn.NewMultiKeychain(&auth.EnvKeychain{EnvironFunc: environFunc}, k8sKeychain, auth.CustomRegistryKeychain{Opts: keychainOpts})
	case <-timeout:
		return regauthn.NewMultiKeychain(&auth.EnvKeychain{EnvironFunc: environFunc}, auth.CustomRegistryKeychain{Opts: keychainOpts})
	}
}
