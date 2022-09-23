// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package ndm

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/test/new-e2e/utils/clients"
	"github.com/DataDog/datadog-agent/test/new-e2e/utils/credentials"
	"github.com/DataDog/datadog-agent/test/new-e2e/utils/infra"
	"golang.org/x/crypto/ssh"

	"github.com/DataDog/test-infra-definitions/aws/ec2/ec2"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/require"
)

const (
	pulumiStackName = "ndm-agent-vm"

	ec2InstanceName = "agent-ci-docker"
	userData        = `#!/bin/bash

set -ex

export DEBIAN_FRONTEND=noninteractive

apt -y update && apt -y install docker.io
`

	dockerNetworkName          = "ndm-net"
	dockerAgentContainerName   = "dd-agent"
	dockerSnmpsimContainerName = "dd-snmpsim"
)

func TestSetup(t *testing.T) {
	credentialsManager := credentials.NewManager()

	// Retrieving necessary secrets
	sshKey, err := credentialsManager.GetCredential(credentials.AWSSSMStore, "agent.ci.awssandbox.ssh")
	require.NoError(t, err)

	apiKey, err := credentialsManager.GetCredential(credentials.AWSSSMStore, "agent.ci.dev.apikey")
	require.NoError(t, err)

	stackOutput, err := infra.GetStackManager().GetStack(context.Background(), "aws/sandbox", pulumiStackName, nil, func(ctx *pulumi.Context) error {
		instance, err := ec2.CreateEC2Instance(ctx, ec2InstanceName, "", ec2.AMD64Arch, "t3.large", "agent-ci-sandbox", userData)
		if err != nil {
			return err
		}

		ctx.Export("private-ip", instance.PrivateIp)
		return nil
	})
	require.NoError(t, err)

	instanceIP, found := stackOutput.Outputs["private-ip"]
	require.True(t, found)

	// Setup Agent
	t.Logf("Connecting through ssh client to %s", instanceIP.Value.(string))
	client, _, err := clients.GetSSHClient("ubuntu", fmt.Sprintf("%s:%d", instanceIP.Value.(string), 22), sshKey, 2*time.Second, 30)
	require.NoError(t, err)
	defer client.Close()

	// Wait for docker to be installed
	require.NoError(t, waitForDocker(t, client, 5*time.Minute))

	// create docker network
	stdout, err := clients.ExecuteCommand(client, fmt.Sprintf("sudo docker network create %s", dockerNetworkName))
	t.Log(stdout)
	require.NoError(t, err)

	// clone integrations core
	_, err = clients.ExecuteCommand(client, "sudo mkdir -p /repos/dd/integrations-core")
	require.NoError(t, err)

	t.Log("git clone integrations-core")
	stdout, err = clients.ExecuteCommand(client, "sudo git clone https://github.com/DataDog/integrations-core.git /repos/dd/integrations-core")
	t.Log(stdout)
	require.NoError(t, err)

	// run the agent container on the VM
	stdout, err = clients.ExecuteCommand(client, fmt.Sprintf("sudo docker run -d --cgroupns host"+
		" --name %s"+
		" -v /var/run/docker.sock:/var/run/docker.sock:ro"+
		" -v /proc/:/host/proc/:ro"+
		" -v /dd/config/:/etc/datadog-agent/"+
		" -v /repos/dd/integrations-core/snmp/datadog_checks/snmp/data/profiles:/etc/datadog-agent/conf.d/snmp.d/profiles/"+
		" -v /sys/fs/cgroup/:/host/sys/fs/cgroup:ro"+
		" --network %s"+
		" -e DD_API_KEY=%s datadog/agent-dev:master", dockerAgentContainerName, dockerNetworkName, apiKey))
	t.Log(stdout)
	require.NoError(t, err)

	t.Log("sudo ls /dd/config")
	stdout, err = clients.ExecuteCommand(client, "sudo ls /dd/config")

	t.Log(stdout)

	require.NoError(t, err)

	stdout, err = clients.ExecuteCommand(client, fmt.Sprintf("sudo docker run -d --cgroupns host"+
		" --name %s"+
		" -v /repos/dd/integrations-core/snmp/tests/compose/data:/usr/snmpsim/data/"+
		" --network %s"+
		" datadog/docker-library:snmp", dockerSnmpsimContainerName, dockerNetworkName))

	t.Log(stdout)
	require.NoError(t, err)
}

func TestSnmpCheck(t *testing.T) {
	credentialsManager := credentials.NewManager()

	sshKey, err := credentialsManager.GetCredential(credentials.AWSSSMStore, "agent.ci.awssandbox.ssh")
	require.NoError(t, err)

	stackOutput, err := infra.GetStackManager().GetStack(context.Background(), "aws/sandbox", pulumiStackName, nil, func(ctx *pulumi.Context) error {
		instance, err := ec2.CreateEC2Instance(ctx, ec2InstanceName, "", ec2.AMD64Arch, "t3.large", "agent-ci-sandbox", userData)
		if err != nil {
			return err
		}

		ctx.Export("private-ip", instance.PrivateIp)
		return nil
	})
	require.NoError(t, err)

	instanceIP, found := stackOutput.Outputs["private-ip"]
	require.True(t, found)

	// Setup Agent
	client, _, err := clients.GetSSHClient("ubuntu", fmt.Sprintf("%s:%d", instanceIP.Value.(string), 22), sshKey, 2*time.Second, 30)
	require.NoError(t, err)
	defer client.Close()

	t.Log("Creating folder for snmp config")
	stdout, err := clients.ExecuteCommand(client, "sudo mkdir -p /dd/config/conf.d/snmp.d")
	t.Log(stdout)
	require.NoError(t, err)

	snmpConfig := `init_config:
  loader: core  # use core check implementation of SNMP integration. recommended
  use_device_id_as_hostname: true  # recommended
instances:
  - ip_address: 'dd-snmpsim'
    community_string: 'public'  # enclose with single quote
    port: 1161
    tags:
    - 'ci:rule'
    - 'dde2test:pducolin'`
	stdout, err = clients.ExecuteCommand(client, fmt.Sprintf("sudo bash -c 'echo \"%s\" > /dd/config/conf.d/snmp.d/conf.yaml'", snmpConfig))
	t.Log(stdout)
	require.NoError(t, err)

	stdout, err = clients.ExecuteCommand(client, fmt.Sprintf("sudo docker exec %s sh -c \"agent check snmp\"", dockerAgentContainerName))
	t.Log(stdout)
	require.NoError(t, err)
}

func TestAgentSNMPWalk(t *testing.T) {
	credentialsManager := credentials.NewManager()

	sshKey, err := credentialsManager.GetCredential(credentials.AWSSSMStore, "agent.ci.awssandbox.ssh")
	require.NoError(t, err)

	stackOutput, err := infra.GetStackManager().GetStack(context.Background(), "aws/sandbox", pulumiStackName, nil, func(ctx *pulumi.Context) error {
		instance, err := ec2.CreateEC2Instance(ctx, ec2InstanceName, "", ec2.AMD64Arch, "t3.large", "agent-ci-sandbox", userData)
		if err != nil {
			return err
		}

		ctx.Export("private-ip", instance.PrivateIp)
		return nil
	})
	require.NoError(t, err)

	instanceIP, found := stackOutput.Outputs["private-ip"]
	require.True(t, found)

	// Setup Agent
	client, _, err := clients.GetSSHClient("ubuntu", fmt.Sprintf("%s:%d", instanceIP.Value.(string), 22), sshKey, 2*time.Second, 30)
	require.NoError(t, err)
	defer client.Close()

	t.Log("sudo ls /dd/config")
	stdout, err := clients.ExecuteCommand(client, "sudo ls /dd/config")

	t.Log(stdout)

	require.NoError(t, err)

	stdout, err = clients.ExecuteCommand(client, fmt.Sprintf("sudo docker exec %s sh -c \"agent snmp walk %s:1161 1.3.6.1.2.1.25.6.3.1 --community-string public\"", dockerAgentContainerName, dockerSnmpsimContainerName))
	// we can assert against the snmp walk stdout
	t.Log(stdout)
	require.NoError(t, err)
}

func waitForDocker(t *testing.T, client *ssh.Client, timeout time.Duration) (err error) {
	// Wait for docker to be installed
	waitForDocker := true
	start := time.Now()
	for waitForDocker {
		if time.Since(start) > timeout {
			return errors.New("Timeout waiting for Docker")
		}
		_, err := clients.ExecuteCommand(client, "sudo docker ps")
		if err == nil {
			waitForDocker = false
		}

		if waitForDocker {
			t.Log("Wait for docker")
			time.Sleep(1 * time.Second)
		}
	}

	return nil
}
