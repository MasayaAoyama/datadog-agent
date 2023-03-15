// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package sbom

import (
	"context"
	"time"

	cyclonedxgo "github.com/CycloneDX/cyclonedx-go"
	"github.com/containerd/containerd"

	cutil "github.com/DataDog/datadog-agent/pkg/util/containerd"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

// Report interface
type Report interface {
	ToCycloneDX() (*cyclonedxgo.BOM, error)
}

// ContainerdAccessor is a function that should return a containerd client
type ContainerdAccessor func() (cutil.ContainerdItf, error)

// ScanOptions describes the SBOM scan options
type ScanOptions struct {
	Analyzers []string
	Timeout   time.Duration
	WaitAfter time.Duration
}

// Collector interface
type Collector interface {
	ScanContainerdImage(ctx context.Context, imageMeta *workloadmeta.ContainerImageMetadata, img containerd.Image, accessor ContainerdAccessor, scanOptions ScanOptions) (Report, error)
	ScanContainerdImageFromFilesystem(ctx context.Context, imgMeta *workloadmeta.ContainerImageMetadata, img containerd.Image, accessor ContainerdAccessor, scanOptions ScanOptions) (Report, error)
	ScanFilesystem(ctx context.Context, path string, scanOptions ScanOptions) (Report, error)
	Close() error
}
