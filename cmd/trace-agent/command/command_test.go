// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package command

import (
	"testing"

	"github.com/DataDog/datadog-agent/cmd/trace-agent/subcommands"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestRootCommand(t *testing.T) {
	fxutil.TestOneShotSubcommand(t,
		[]*cobra.Command{MakeRootCommand("foo")},
		[]string{"--config", "PATH"},
		test,
		func(cliParams *subcommands.GlobalParams) {
			require.Equal(t, "PATH", cliParams.ConfPath)
		})
}

func test(cliParams *subcommands.GlobalParams) error {
	return nil
}
