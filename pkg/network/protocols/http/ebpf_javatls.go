// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/java"
	nettelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
)

const (
	agentUSMJar           = "agent-usm.jar"
	javaTLSConnectionsMap = "java_tls_connections"
)

var (
	// path to our java USM agent TLS tracer
	javaUSMAgentJarPath = ""

	// default arguments passed to the injected agent-usm.jar
	javaUSMAgentArgs = ""
	// authID is used here as an identifier, simple proof of authenticity
	// between the injected java process and the ebpf ioctl that receive the payload
	authID = int64(0)
)

type JavaTLSProgram struct {
	manager        *nettelemetry.Manager
	processMonitor *monitor.ProcessMonitor
	cleanupExec    func()
}

// Static evaluation to make sure we are not breaking the interface.
var _ subprogram = &JavaTLSProgram{}

func newJavaTLSProgram(c *config.Config) *JavaTLSProgram {
	if !c.EnableHTTPSMonitoring || !c.EnableJavaTLSSupport {
		return nil
	}

	if !c.EnableRuntimeCompiler {
		log.Errorf("java TLS support requires runtime-compilation to be enabled")
		return nil
	}

	javaUSMAgentArgs = c.JavaAgentArgs
	javaUSMAgentJarPath = filepath.Join(c.JavaDir, AgentUSMJar)

	jar, err := os.Open(javaUSMAgentJarPath)
	if err != nil {
		log.Errorf("java TLS can't access to agent-usm.jar file %s : %s", javaUSMAgentJarPath, err)
		return nil
	}
	jar.Close()

	mon := monitor.GetProcessMonitor()
	return &JavaTLSProgram{
		processMonitor: mon,
	}
}

func (p *JavaTLSProgram) ConfigureManager(m *nettelemetry.Manager) {
	p.manager = m
	p.manager.Maps = append(p.manager.Maps, []*manager.Map{
		{Name: javaTLSConnectionsMap},
	}...)

	p.manager.Probes = append(m.Probes,
		&manager.Probe{ProbeIdentificationPair: manager.ProbeIdentificationPair{
			EBPFSection:  "kprobe/do_vfs_ioctl",
			EBPFFuncName: "kprobe__do_vfs_ioctl",
			UID:          probeUID,
		},
			KProbeMaxActive: maxActive,
		},
	)
	rand.Seed(int64(os.Getpid()) + time.Now().UnixMicro())
	authID = rand.Int63()
}

func (p *JavaTLSProgram) ConfigureOptions(options *manager.Options) {
	options.ActivatedProbes = append(options.ActivatedProbes,
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "kprobe/do_vfs_ioctl",
				EBPFFuncName: "kprobe__do_vfs_ioctl",
				UID:          probeUID,
			},
		})
}

func (p *JavaTLSProgram) GetAllUndefinedProbes() (probeList []manager.ProbeIdentificationPair) {

	probeList = append(probeList, manager.ProbeIdentificationPair{
		EBPFSection:  "kprobe/do_vfs_ioctl",
		EBPFFuncName: "kprobe__do_vfs_ioctl"})

	return probeList
}

func newJavaProcess(pid uint32) {
	args := javaUSMAgentArgs
	if len(args) > 0 {
		args += " "
	}
	args += "dd.usm.authID=" + strconv.FormatInt(authID, 10)
	if err := java.InjectAgent(int(pid), javaUSMAgentJarPath, args); err != nil {
		log.Error(err)
	}
}

func (p *JavaTLSProgram) Start() {
	var err error
	p.cleanupExec, err = p.processMonitor.Subscribe(&monitor.ProcessCallback{
		Event:    monitor.EXEC,
		Metadata: monitor.NAME,
		Regex:    regexp.MustCompile("^java$"),
		Callback: newJavaProcess,
	})
	if err != nil {
		log.Errorf("process monitor Subscribe() error: %s", err)
		return
	}
}

func (p *JavaTLSProgram) Stop() {
	if p.cleanupExec != nil {
		p.cleanupExec()
	}
}
