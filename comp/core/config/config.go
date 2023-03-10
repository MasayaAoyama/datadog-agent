// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"strings"
	"testing"

	"go.uber.org/fx"

	secconfig "github.com/DataDog/datadog-agent/cmd/security-agent/config"
	"github.com/DataDog/datadog-agent/pkg/config"
)

// cfg implements the Component.
type cfg struct {
	// this component is currently implementing a thin wrapper around pkg/config,
	// and uses globals in that package.
	config.Config

	// warnings are the warnings generated during setup
	warnings *config.Warnings
}

type dependencies struct {
	fx.In

	Params Params
}

func newConfig(deps dependencies) (Component, error) {
	warnings, err := setupConfig(deps)
	if err != nil {
		return nil, err
	}

	if deps.Params.configLoadSecurityAgent {
		err = secconfig.Merge(deps.Params.securityAgentConfigFilePaths)
	}

	// Overrides are explicit and will take precedence over any other
	// setting: used in testing
	for k, v := range deps.Params.overrides {
		config.Datadog.Set(k, v)
	}

	return &cfg{Config: config.Datadog, warnings: warnings}, err
}

func (c *cfg) Warnings() *config.Warnings {
	return c.warnings
}

func (c *cfg) Object() config.ConfigReader {
	return c.Config
}

// NewMock exported mock builder to allow modifying mocks that might be
// supplied in tests and used for dep injection.
func newMock(deps dependencies, t testing.TB) Component {
	old := config.Datadog
	config.Datadog = config.NewConfig("mock", "XXXX", strings.NewReplacer())
	c := &cfg{
		warnings: &config.Warnings{},
		Config:   config.Datadog,
	}

	// call InitConfig to set defaults.
	config.InitConfig(config.Datadog)

	// Viper's `GetXxx` methods read environment variables at the time they are
	// called, if those names were passed explicitly to BindEnv*(), so we must
	// also strip all `DD_` environment variables for the duration of the test.
	// oldEnv := os.Environ()
	// for _, kv := range oldEnv {
	// 	if strings.HasPrefix(kv, "DD_") {
	// 		kvslice := strings.SplitN(kv, "=", 2)
	// 		os.Unsetenv(kvslice[0])
	// 	}
	// }
	// t.Cleanup(func() {
	// 	for _, kv := range oldEnv {
	// 		kvslice := strings.SplitN(kv, "=", 2)
	// 		os.Setenv(kvslice[0], kvslice[1])
	// 	}
	// })

	setupConfig(deps)

	// Overrides are explicit and will take precedence over any other
	// setting
	for k, v := range deps.Params.overrides {
		config.Datadog.Set(k, v)
	}

	// swap the existing config back at the end of the test.
	t.Cleanup(func() { config.Datadog = old })

	return c
}
