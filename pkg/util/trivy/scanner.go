// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build trivy
// +build trivy

package trivy

import (
	"context"
	"errors"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"

	cutil "github.com/DataDog/datadog-agent/pkg/util/containerd"
	"github.com/containerd/containerd"
)

const (
	imagesToScanBufferSize = 50
	fsToScanBufferSize     = 1
)

var _service *Scanner

type scanRequest struct {
	scanOptions sbom.ScanOptions
	onSuccess   sbom.ScanSuccessCallback
	onError     sbom.ScanErrorCallback
}

func (r scanRequest) triggerCallbacks(report sbom.Report, createdAt time.Time, generationDuration time.Duration, err error) {
	if err != nil {
		if r.onError != nil {
			r.onError(err)
		}
	} else {
		if r.onSuccess != nil {
			r.onSuccess(report, createdAt, generationDuration)
		}
	}
}

func (r scanRequest) waitInterval(ctx context.Context) {
	t := time.NewTimer(r.scanOptions.WaitAfter)
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	t.Stop()

}

func (r scanRequest) withContext(parent context.Context) (scanContext context.Context, cancel context.CancelFunc) {
	if r.scanOptions.Timeout != 0 {
		scanContext, cancel = context.WithTimeout(parent, r.scanOptions.Timeout)
	} else {
		scanContext, cancel = context.WithCancel(parent)
	}
	return
}

type imageScanRequest struct {
	scanRequest
	imageMeta          *workloadmeta.ContainerImageMetadata
	img                containerd.Image
	client             cutil.ContainerdItf
	containerdAccessor sbom.ContainerdAccessor
	fromFilesystem     bool
}

type fsScanRequest struct {
	scanRequest
	path string
}

type Scanner struct {
	collector         sbom.Collector
	running           bool
	imagesToScan      chan imageScanRequest
	filesystemsToScan chan fsScanRequest
}

func (s *Scanner) scanImage(imageMeta *workloadmeta.ContainerImageMetadata, image containerd.Image, client cutil.ContainerdItf, fromFilesystem bool, onSuccess sbom.ScanSuccessCallback, onError func(err error), opts sbom.ScanOptions) error {
	select {
	case s.imagesToScan <- imageScanRequest{
		scanRequest: scanRequest{
			scanOptions: opts,
			onSuccess:   onSuccess,
			onError:     onError,
		},
		imageMeta:      imageMeta,
		img:            image,
		client:         client,
		fromFilesystem: fromFilesystem,
	}:
		return nil
	default:
		return errors.New("container image queue is full")
	}
}

func (s *Scanner) ScanContainerdImage(imageMeta *workloadmeta.ContainerImageMetadata, image containerd.Image, client cutil.ContainerdItf, onSuccess sbom.ScanSuccessCallback, onError sbom.ScanErrorCallback, opts sbom.ScanOptions) error {
	return s.scanImage(imageMeta, image, client, false, onSuccess, onError, opts)
}

func (s *Scanner) ScanContainerdImageFromFilesystem(imageMeta *workloadmeta.ContainerImageMetadata, image containerd.Image, client cutil.ContainerdItf, onSuccess sbom.ScanSuccessCallback, onError sbom.ScanErrorCallback, opts sbom.ScanOptions) error {
	return s.scanImage(imageMeta, image, client, true, onSuccess, onError, opts)
}

func (s *Scanner) ScanFilesystem(path string, onSuccess sbom.ScanSuccessCallback, onError sbom.ScanErrorCallback, opts sbom.ScanOptions) error {
	select {
	case s.filesystemsToScan <- fsScanRequest{
		scanRequest: scanRequest{
			onSuccess:   onSuccess,
			onError:     onError,
			scanOptions: opts,
		},
		path: path,
	}:
		return nil
	default:
		return errors.New("host fs queue is full")
	}
}

func (s *Scanner) Start(ctx context.Context) {
	if s.running == true {
		return
	}

	go func() {
		s.running = true
		defer func() { s.running = false }()

		for {
			select {
			// We don't want to keep scanning if image channel is not empty but context is expired
			case <-ctx.Done():
				if err := s.collector.Close(); err != nil {
					log.Errorf("Failed to close collector: %s", err)
				}
				return

			case request, ok := <-s.imagesToScan:
				// Channel has been closed we should exit
				if !ok {
					return
				}

				scanContext, cancel := request.withContext(ctx)
				createdAt := time.Now()

				var report sbom.Report
				var err error
				if request.fromFilesystem {
					report, err = s.collector.ScanContainerdImageFromFilesystem(scanContext, request.imageMeta, request.img, request.containerdAccessor, request.scanOptions)
				} else {
					report, err = s.collector.ScanContainerdImage(scanContext, request.imageMeta, request.img, request.containerdAccessor, request.scanOptions)
				}

				generationDuration := time.Since(createdAt)

				cancel()
				request.triggerCallbacks(report, createdAt, generationDuration, err)
				request.waitInterval(ctx)

			case request, ok := <-s.filesystemsToScan:
				// Channel has been closed we should exit
				if !ok {
					return
				}

				scanContext, cancel := request.withContext(ctx)
				createdAt := time.Now()

				bom, err := s.collector.ScanFilesystem(scanContext, request.path, request.scanOptions)

				generationDuration := time.Since(createdAt)

				cancel()
				request.triggerCallbacks(bom, createdAt, generationDuration, err)
				request.waitInterval(ctx)
			}
		}
	}()
}

func GetScanner(config config.Config) (*Scanner, error) {
	if _service == nil {
		trivyConfiguration := DefaultCollectorConfig(config.GetString("sbom.cache_directory"))
		trivyConfiguration.ClearCacheOnClose = config.GetBool("sbom.clear_cache_on_exit")

		collector, err := NewCollector(trivyConfiguration)
		if err != nil {
			return nil, err
		}

		_service = &Scanner{
			collector:         collector,
			imagesToScan:      make(chan imageScanRequest, imagesToScanBufferSize),
			filesystemsToScan: make(chan fsScanRequest, fsToScanBufferSize),
		}
		_service.Start(context.Background())
	}
	return _service, nil
}
