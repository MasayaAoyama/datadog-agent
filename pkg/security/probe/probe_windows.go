// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows
// +build windows

package probe

import (
	"context"
	"sync"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"

	"github.com/DataDog/datadog-agent/pkg/eventmonitor/config"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/windowsdriver/procmon"
)

// EventHandler represents an handler for the events sent by the probe
type EventHandler interface {
	HandleEvent(event *model.Event)
}

type Probe struct {
	Opts         Opts
	Config       *config.Config
	StatsdClient statsd.ClientInterface
	startTime    time.Time
	ctx          context.Context
	cancelFnc    context.CancelFunc
	wg           sync.WaitGroup

	pm      *procmon.WinProcmon
	onStart chan *procmon.ProcessStartNotification
	onStop  chan *procmon.ProcessStopNotification
}

// AddEventHandler set the probe event handler
func (p *Probe) AddEventHandler(eventType model.EventType, handler EventHandler) error {
	return nil
}

// Init initializes the probe
func (p *Probe) Init() error {
	p.startTime = time.Now()

	pm, err := procmon.NewWinProcMon(p.onStart, p.onStop)
	if err != nil {
		return nil
	}
	p.pm = pm

	return nil
}

// Setup the runtime security probe
func (p *Probe) Setup() error {
	return nil
}

// Start processing events
func (p *Probe) Start() error {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			select {
			case <-p.ctx.Done():
				return
			case start := <-p.onStart:
				log.Infof("Start notification: %v", start)
			case stop := <-p.onStop:
				log.Infof("Stop notification: %v", stop)

			}
		}
	}()
	p.pm.Start()
	return nil
}

// Snapshot runs the different snapshot functions of the resolvers that
// require to sync with the current state of the system
func (p *Probe) Snapshot() error {
	//return p.resolvers.Snapshot()
	return nil
}

// Close the probe
func (p *Probe) Close() error {
	p.pm.Stop()
	p.cancelFnc()
	p.wg.Wait()
	return nil
}

// SendStats sends statistics about the probe to Datadog
func (p *Probe) SendStats() error {
	//p.resolvers.TCResolver.SendTCProgramsStats(p.StatsdClient)
	//
	//return p.monitor.SendStats()
	return nil
}

// GetDebugStats returns the debug stats
func (p *Probe) GetDebugStats() map[string]interface{} {
	debug := map[string]interface{}{
		"start_time": p.startTime.String(),
	}
	return debug
}

// NewProbe instantiates a new runtime security agent probe
func NewProbe(config *config.Config, opts Opts) (*Probe, error) {
	opts.normalize()

	ctx, cancel := context.WithCancel(context.Background())

	p := &Probe{
		Opts:         opts,
		Config:       config,
		ctx:          ctx,
		cancelFnc:    cancel,
		StatsdClient: opts.StatsdClient,
		onStart:      make(chan *procmon.ProcessStartNotification),
		onStop:       make(chan *procmon.ProcessStopNotification),
	}
	return p, nil
}
