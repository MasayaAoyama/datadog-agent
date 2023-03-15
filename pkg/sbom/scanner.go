// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package sbom

import (
	"time"

	"github.com/containerd/containerd"

	cutil "github.com/DataDog/datadog-agent/pkg/util/containerd"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

// ScanSuccessCallback defines the callback called when SBOM was successfully generated
type ScanSuccessCallback func(Report, time.Time, time.Duration)

// ScanErrorCallback defines the callback called when an error occurred when generating SBOM
type ScanErrorCallback func(err error)

// Scanner interface
type Scanner interface {
	ScanContainerdImage(*workloadmeta.ContainerImageMetadata, containerd.Image, cutil.ContainerdItf, ScanSuccessCallback, ScanErrorCallback, ScanOptions) error
	ScanContainerdImageFromFilesystem(*workloadmeta.ContainerImageMetadata, containerd.Image, cutil.ContainerdItf, ScanSuccessCallback, ScanErrorCallback, ScanOptions) error
	ScanFilesystem(string, ScanSuccessCallback, ScanErrorCallback, ScanOptions) error
}
