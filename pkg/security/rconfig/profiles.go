// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package rconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	proto "github.com/DataDog/agent-payload/v5/cws/dumpsv1"

	"github.com/DataDog/datadog-agent/pkg/config/remote"
	"github.com/DataDog/datadog-agent/pkg/config/remote/data"
	"github.com/DataDog/datadog-agent/pkg/remoteconfig/state"
	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type ProfileConfig struct {
	Tags    []string
	Profile []byte
}

type RCProfileProvider struct {
	sync.RWMutex

	client   *remote.Client
	tagQueue []string

	onNewProfileCallback func(selector cgroupModel.WorkloadSelector, profile *proto.SecurityProfile)
}

// Close stops the client
func (r *RCProfileProvider) Stop() error {
	r.client.Close()
	return nil
}

func (r *RCProfileProvider) rcProfilesUpdateCallback(configs map[string]state.ConfigCWSProfiles) {
	log.Info("new profiles from remote-config policy provider")

	// move to the next tag
	if len(r.tagQueue) > 0 {
		selector, err := tagToSelector(r.tagQueue[0])
		if err != nil {
			log.Error(err)
			return
		}

		for _, config := range configs {
			var profCfg ProfileConfig
			if err := json.Unmarshal(config.Config, &profCfg); err != nil {
				log.Errorf("couldn't decode json profile: %w", err)
				return
			}

			profile := &proto.SecurityProfile{}
			if err = profile.UnmarshalVT([]byte(profCfg.Profile)); err != nil {
				log.Errorf("couldn't decode protobuf profile: %w", err)
				return
			}

			if len(utils.GetTagValue("image_tag", profile.Tags)) == 0 {
				profile.Tags = append(profile.Tags, "image_tag:latest")
			}

			r.onNewProfileCallback(selector, profile)
		}

		r.tagQueue = r.tagQueue[1:]
	}

	if len(r.tagQueue) > 0 {
		r.client.UpdateClusterName(r.tagQueue[0])
	}
}

// Start starts the Remote Config profile provider and subscribes to updates
func (r *RCProfileProvider) Start(ctx context.Context) error {
	log.Info("remote-config profile provider started")

	r.client.RegisterCWSProfilesUpdate(r.rcProfilesUpdateCallback)

	r.client.Start()

	go func() {
		<-ctx.Done()
		r.Stop()
	}()

	// set the first tag
	if len(r.tagQueue) > 0 {
		r.client.UpdateClusterName(r.tagQueue[0])
	}

	return nil
}

func selectorToTag(selector *cgroupModel.WorkloadSelector) string {
	return selector.Image + ":::" + selector.Tag
}

func tagToSelector(tag string) (cgroupModel.WorkloadSelector, error) {
	var selector cgroupModel.WorkloadSelector

	els := strings.Split(tag, ":::")
	if len(els) != 2 {
		return selector, fmt.Errorf("tag format incorrect: %s", tag)
	}
	return cgroupModel.NewWorkloadSelector(els[0], els[1]), nil
}

// UpdateWorkloadSelectors updates the selectors used to query profiles
func (r *RCProfileProvider) UpdateWorkloadSelectors(selectors []cgroupModel.WorkloadSelector) {
	r.Lock()
	defer r.Unlock()

	for _, selector := range selectors {
		candidate := selectorToTag(&selector)

		var present bool
		for _, tag := range r.tagQueue {
			if candidate == tag {
				present = true
				break
			}
		}

		if !present {
			r.tagQueue = append(r.tagQueue, candidate)
		}
	}

	if len(r.tagQueue) == 1 {
		r.client.UpdateClusterName(r.tagQueue[0])
	}
}

// SetOnNewProfileCallback sets the onNewProfileCallback function
func (r *RCProfileProvider) SetOnNewProfileCallback(onNewProfileCallback func(selector cgroupModel.WorkloadSelector, profile *proto.SecurityProfile)) {
	r.onNewProfileCallback = onNewProfileCallback
}

// NewRCPolicyProvider returns a new Remote Config based policy provider
func NewRCProfileProvider() (*RCProfileProvider, error) {
	agentVersion, err := utils.GetAgentSemverVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to parse agent version: %v", err)
	}

	c, err := remote.NewUnverifiedGRPCClient(agentName, agentVersion.String(), []data.Product{data.ProductCWSProfile}, securityAgentRCPollInterval)
	if err != nil {
		return nil, err
	}

	r := &RCProfileProvider{
		client: c,
	}

	return r, nil
}
