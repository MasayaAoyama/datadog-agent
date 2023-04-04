// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package profile

import (
	"sync"

	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/dump"
)

type Status uint32

const (
	UnknownStatus Status = iota
	// Alert anomaly detections will trigger an alert
	Alert
	// Kill anomaly detections will kill the process that triggered them
	Kill
)

func (s Status) String() string {
	switch s {
	case Alert:
		return "alert"
	case Kill:
		return "kill"
	default:
		return "unknown"
	}
}

// SecurityProfile defines a security profile
type SecurityProfile struct {
	sync.Mutex
	loadedInKernel bool
	selector       cgroupModel.WorkloadSelector

	// Instances is the list of workload instances to witch the profile should apply
	Instances []*cgroupModel.CacheEntry

	// Status is the status of the profile
	Status Status

	// Version is the version of a Security Profile
	Version string

	// Metadata contains metadata for the current profile
	Metadata dump.Metadata

	// Tags defines the tags used to compute this profile
	Tags []string

	// Syscalls is the syscalls profile
	Syscalls []uint32

	// ProcessActivityTree contains the activity tree of the Security Profile
	ProcessActivityTree []*dump.ProcessActivityNode
}

// reset empties all internal fields so that this profile can be used again in the future
func (p *SecurityProfile) reset() {
	p.loadedInKernel = false
	p.Instances = nil
}

// NewSecurityProfile creates a new instance of Security Profile
func NewSecurityProfile(selector cgroupModel.WorkloadSelector) *SecurityProfile {
	return &SecurityProfile{
		selector: selector,
	}
}

type ProcessActivityNodeAndParent struct {
	node   *dump.ProcessActivityNode
	parent *ProcessActivityNodeAndParent
}

func NewProcessActivityNodeAndParent(node *dump.ProcessActivityNode, parent *ProcessActivityNodeAndParent) *ProcessActivityNodeAndParent {
	return &ProcessActivityNodeAndParent{
		node:   node,
		parent: parent,
	}
}

func ProcessActivityTreeWalk(processActivityTree []*dump.ProcessActivityNode,
	walkFunc func(pNode *ProcessActivityNodeAndParent) bool) []*dump.ProcessActivityNode {
	var result []*dump.ProcessActivityNode
	if len(processActivityTree) <= 0 {
		return result
	}

	var nodes []*ProcessActivityNodeAndParent
	var node *ProcessActivityNodeAndParent
	for _, n := range processActivityTree {
		nodes = append(nodes, NewProcessActivityNodeAndParent(n, nil))
	}
	node = nodes[0]
	nodes = nodes[1:]

	for node != nil {
		if walkFunc(node) {
			result = append(result, node.node)
		}

		for _, child := range node.node.Children {
			nodes = append(nodes, NewProcessActivityNodeAndParent(child, node))
		}
		if len(nodes) > 0 {
			node = nodes[0]
			nodes = nodes[1:]
		} else {
			node = nil
		}
	}
	return result
}

func (p *SecurityProfile) findProfileProcessNodes(pc *model.ProcessContext) []*dump.ProcessActivityNode {
	if pc == nil {
		return []*dump.ProcessActivityNode{}
	}

	var parent *model.ProcessContext
	if pc.Ancestor == nil {
		parent = nil
	} else {
		parent = pc.GetNextAncestorBinary()
	}

	return ProcessActivityTreeWalk(p.ProcessActivityTree, func(node *ProcessActivityNodeAndParent) bool {
		// check process
		if !node.node.Matches(&pc.Process, false) {
			return false
		}
		// check parent
		if node.parent == nil && parent == nil {
			return true
		}
		if node.parent == nil || parent == nil {
			return false
		}
		return node.parent.node.Matches(&parent.Process, false)
	})
}

func findFileInNode(node *dump.ProcessActivityNode, file *model.FileEvent) bool {
	childs := node.Files
	var child *dump.FileActivityNode = nil
	var ok bool
	currentPath := file.PathnameStr
	for {
		parent, nextParentIndex := dump.ExtractFirstParent(currentPath)
		if nextParentIndex == 0 {
			if child != nil && child.Name == file.BasenameStr {
				// TODO: redo match mode/flags, once stored values are working as expected
				// return uint32(file.Flags) == child.Open.Flags&uint32(file.Flags) &&
				// 	uint32(file.Mode) == child.Open.Mode&uint32(file.Mode)
				return true
			} else {
				return false
			}
		}
		child, ok = childs[parent] // TODO: handle patterns
		if !ok {
			return false
		}
		childs = child.Children
		currentPath = currentPath[nextParentIndex:]
	}
	return false
}

func findFileInNodes(nodes []*dump.ProcessActivityNode, event *model.Event) bool {
	fileEvent := &event.Open.File
	if fileEvent.PathnameStr == "" {
		event.FieldHandlers.ResolveFilePath(event, fileEvent)
	}
	if event.PathResolutionError != nil {
		return false
	}

	for _, node := range nodes {
		if findFileInNode(node, fileEvent) {
			return true
		}
	}
	return false
}

func findDNSInNodes(nodes []*dump.ProcessActivityNode, event *model.Event) bool {
	for _, node := range nodes {
		dnsNode, ok := node.DNSNames[event.DNS.Name]
		if !ok {
			continue
		}
		for _, req := range dnsNode.Requests {
			if req.Type == event.DNS.Type {
				return true
			}
		}
	}
	return false
}

func findBindInNodes(nodes []*dump.ProcessActivityNode, event *model.Event) bool {
	evtFamily := model.AddressFamily(event.Bind.AddrFamily).String()
	evtIP := event.Bind.Addr.IPNet.IP.String()
	evtPort := event.Bind.Addr.Port

	for _, node := range nodes {
		for _, socket := range node.Sockets {
			if socket.Family != evtFamily {
				continue
			}

			for _, bind := range socket.Bind {
				if bind.Port == evtPort && bind.IP == evtIP {
					return true
				}
			}
		}
	}
	return false
}
