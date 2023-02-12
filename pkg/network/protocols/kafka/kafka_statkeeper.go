// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package kafka

import (
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"sync"
)

type kafkaStatKeeper struct {
	stats      map[Key]*RequestStat
	statsMutex sync.RWMutex
	maxEntries int
	telemetry  *telemetry
}

func newKafkaStatkeeper(c *config.Config, telemetry *telemetry) *kafkaStatKeeper {
	return &kafkaStatKeeper{
		stats:      make(map[Key]*RequestStat),
		maxEntries: c.MaxKafkaStatsBuffered,
		telemetry:  telemetry,
	}
}

func (statKeeper *kafkaStatKeeper) Process(tx *ebpfKafkaTx) {
	statKeeper.add(tx)
}

func (statKeeper *kafkaStatKeeper) add(transaction *ebpfKafkaTx) {
	key := Key{
		RequestAPIKey:  transaction.Request_api_key,
		RequestVersion: transaction.Request_api_version,
		TopicName:      transaction.TopicName(),
		KeyTuple: KeyTuple{
			SrcIPHigh: transaction.SrcIPHigh(),
			SrcIPLow:  transaction.SrcIPLow(),
			SrcPort:   transaction.SrcPort(),
			DstIPHigh: transaction.DstIPHigh(),
			DstIPLow:  transaction.DstIPLow(),
			DstPort:   transaction.DstPort(),
		},
	}
	statKeeper.statsMutex.Lock()
	defer statKeeper.statsMutex.Unlock()
	requestStats, ok := statKeeper.stats[key]
	if !ok {
		if len(statKeeper.stats) >= statKeeper.maxEntries {
			statKeeper.telemetry.dropped.Add(1)
			return
		}
		requestStats = new(RequestStat)
		statKeeper.stats[key] = requestStats
	}
	requestStats.Count++
}

func (statKeeper *kafkaStatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	statKeeper.statsMutex.RLock()
	defer statKeeper.statsMutex.RUnlock()
	ret := statKeeper.stats // No deep copy needed since `statKeeper.stats` gets reset
	statKeeper.stats = make(map[Key]*RequestStat)
	return ret
}