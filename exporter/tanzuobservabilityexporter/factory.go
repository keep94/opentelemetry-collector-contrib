// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tanzuobservabilityexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/tanzuobservabilityexporter"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/exporter/exporterhelper"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
)

const exporterType = "tanzuobservability"

// NewFactory creates a factory for the exporter.
func NewFactory() component.ExporterFactory {
	return component.NewExporterFactory(
		exporterType,
		createDefaultConfig,
		component.WithTracesExporter(createTracesExporter),
		component.WithMetricsExporter(createMetricsExporter),
	)
}

func createDefaultConfig() config.Exporter {
	return &Config{
		ExporterSettings: config.NewExporterSettings(config.NewComponentID(exporterType)),
		QueueSettings:    exporterhelper.NewDefaultQueueSettings(),
		RetrySettings:    exporterhelper.NewDefaultRetrySettings(),
	}
}

// createTracesExporter implements exporterhelper.CreateTracesExporter and creates
// an exporter for traces using this configuration
func createTracesExporter(
	_ context.Context,
	set component.ExporterCreateSettings,
	cfg config.Exporter,
) (component.TracesExporter, error) {
	tobsCfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", cfg)
	}
	if err := tobsCfg.sanitize(); err != nil {
		return nil, err
	}
	exp, err := newTracesExporter(set, cfg)
	if err != nil {
		return nil, err
	}

	return exporterhelper.NewTracesExporter(
		cfg,
		set,
		exp.pushTraceData,
		exporterhelper.WithQueue(tobsCfg.QueueSettings),
		exporterhelper.WithRetry(tobsCfg.RetrySettings),
		exporterhelper.WithShutdown(exp.shutdown),
	)
}

func createMetricsExporter(
	_ context.Context,
	set component.ExporterCreateSettings,
	cfg config.Exporter,
) (component.MetricsExporter, error) {
	tobsCfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", cfg)
	}
	if err := tobsCfg.sanitize(); err != nil {
		return nil, err
	}
	exp, err := newMetricsExporter(set, cfg, createMetricsConsumer)
	if err != nil {
		return nil, err
	}

	exporter, err := exporterhelper.NewMetricsExporter(
		cfg,
		set,
		exp.pushMetricsData,
		exporterhelper.WithQueue(tobsCfg.QueueSettings),
		exporterhelper.WithRetry(tobsCfg.RetrySettings),
		exporterhelper.WithShutdown(exp.shutdown),
	)
	if err != nil {
		return nil, err
	}
	return resourcetotelemetry.WrapMetricsExporter(
		tobsCfg.Metrics.ResourceAttributes,
		exporter,
	), nil
}
