// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package systemProbe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-agent/test/new-e2e/utils/credentials"
	"github.com/DataDog/datadog-agent/test/new-e2e/utils/infra"
	"github.com/DataDog/test-infra-definitions/aws"
	"github.com/DataDog/test-infra-definitions/aws/scenarios/microVMs/microvms"
	"github.com/DataDog/test-infra-definitions/command"

	"github.com/pulumi/pulumi-command/sdk/go/command/remote"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type TestEnv struct {
	context context.Context
	envName string
	name    string

	ARM64InstanceIP  string
	X86_64InstanceIP string
	StackOutput      auto.UpResult
}

var (
	SSHKeyFile           = filepath.Join(".", "/", "aws-ssh-key")
	vmConfig             = filepath.Join(".", "systemProbe", "config", "vmconfig.json")
	DD_AGENT_TESTING_DIR = os.Getenv("DD_AGENT_TESTING_DIR")
	sshKeyX86            = os.Getenv("LibvirtSSHKeyX86")
	sshKeyArm            = os.Getenv("LibvirtSSHKeyARM")
)

func NewTestEnv(name, securityGroups, subnets, x86InstanceType, armInstanceType string) (*TestEnv, error) {
	systemProbeTestEnv := &TestEnv{
		context: context.Background(),
		envName: "aws/sandbox",
		name:    fmt.Sprintf("microvm-scenario-%s", name),
	}

	awsManager := credentials.NewManager()
	sshkey, err := awsManager.GetCredential(credentials.AWSSSMStore, "ci.datadog-agent.aws_ec2_kitchen_ssh_key")
	if err != nil {
		return nil, err
	}

	// Write ssh key to file
	f, err := os.Create(SSHKeyFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	f.WriteString(sshkey)

	stackManager := infra.GetStackManager()

	config := auto.ConfigMap{
		"ddinfra:aws/defaultARMInstanceType": auto.ConfigValue{Value: armInstanceType},
		"ddinfra:aws/defaultInstanceType":    auto.ConfigValue{Value: x86InstanceType},
		"ddinfra:aws/defaultKeyPairName":     auto.ConfigValue{Value: "datadog-agent-kitchen"},
		"ddinfra:aws/defaultPrivateKeyPath":  auto.ConfigValue{Value: SSHKeyFile},
		"ddinfra:aws/defaultSecurityGroups":  auto.ConfigValue{Value: securityGroups},
		"ddinfra:aws/defaultSubnets":         auto.ConfigValue{Value: subnets},
		"microvm:microVMConfigFile":          auto.ConfigValue{Value: vmConfig},
		"microvm:libvirtSSHKeyFileX86":       auto.ConfigValue{Value: sshKeyX86},
		"microvm:libvirtSSHKeyFileArm":       auto.ConfigValue{Value: sshKeyArm},
	}

	upResult, err := stackManager.GetStack(systemProbeTestEnv.context, systemProbeTestEnv.envName, systemProbeTestEnv.name, config, func(ctx *pulumi.Context) error {
		awsEnvironment, err := aws.NewEnvironment(ctx)
		if err != nil {
			return fmt.Errorf("aws new environment: %w", err)
		}

		scenarioDone, err := microvms.RunAndReturnInstances(ctx, awsEnvironment)
		if err != nil {
			return fmt.Errorf("setup micro-vms in remote instance: %w", err)
		}

		for _, instance := range scenarioDone.Instances {
			remoteRunner, err := command.NewRunner(*awsEnvironment.CommonEnvironment, "remote-runner-"+instance.Arch, instance.Connection, func(r *command.Runner) (*remote.Command, error) {
				return command.WaitForCloudInit(awsEnvironment.Ctx, r)
			})

			filemanager := command.NewFileManager(remoteRunner)
			_, err = filemanager.CopyFile(
				fmt.Sprintf("%s/site-cookbooks-%s.tar.gz", DD_AGENT_TESTING_DIR, instance.Arch),
				fmt.Sprintf("/tmp/site-cookbooks-%s.tar.gz", instance.Arch),
				pulumi.DependsOn(scenarioDone.Dependencies),
			)
			if err != nil {
				return fmt.Errorf("copy file: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create stack: %w", err)
	}

	b, err := json.MarshalIndent(upResult.Summary, "", "	")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(b))

	systemProbeTestEnv.StackOutput = upResult

	outputX86, found := upResult.Outputs["x86_64-instance-ip"]
	if found {
		systemProbeTestEnv.X86_64InstanceIP = outputX86.Value.(string)
	}
	outputARM, found := upResult.Outputs["arm64-instance-ip"]
	if found {
		systemProbeTestEnv.ARM64InstanceIP = outputARM.Value.(string)
	}

	return systemProbeTestEnv, nil
}

func (testEnv *TestEnv) Destroy() error {
	return infra.GetStackManager().DeleteStack(testEnv.context, testEnv.envName, testEnv.name)
}