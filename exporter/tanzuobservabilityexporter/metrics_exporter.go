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

	"github.com/wavefronthq/wavefront-sdk-go/histogram"
	"github.com/wavefronthq/wavefront-sdk-go/senders"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/model/pdata"
)

type metricsExporter struct {
	consumer *metricsConsumer
}

func largestKeyValuePair(tags map[string]string) string {
	result := ""
	for key, value := range tags {
		if len(key)+len(value)+1 > len(result) {
			result = fmt.Sprintf("%s=%s", key, value)
		}
	}
	return result
}

type printSender struct {
	S senders.Sender
}

func (p *printSender) SendMetric(name string, value float64, ts int64, source string, tags map[string]string) error {
	largestTag := largestKeyValuePair(tags)
	fmt.Printf("ASDF sending metric: %s, len: %d, largest tag: '%s'\n", name, len(largestTag), largestTag)
	return p.S.SendMetric(name, value, ts, source, tags)
}

func (p *printSender) SendDeltaCounter(name string, value float64, source string, tags map[string]string) error {
	largestTag := largestKeyValuePair(tags)
	fmt.Printf("ASDF sending metric: %s, len: %d, largest tag: '%s'\n", name, len(largestTag), largestTag)
	return p.S.SendDeltaCounter(name, value, source, tags)
}

func (p *printSender) SendDistribution(name string, centroids []histogram.Centroid, hgs map[histogram.Granularity]bool, ts int64, source string, tags map[string]string) error {
	largestTag := largestKeyValuePair(tags)
	fmt.Printf("ASDF sending metric: %s, len: %d, largest tag: '%s'\n", name, len(largestTag), largestTag)
	return p.S.SendDistribution(name, centroids, hgs, ts, source, tags)
}

func (p *printSender) Flush() error {
	fmt.Println("ASDF Flushing...")
	return p.S.Flush()
}

func (p *printSender) Close() {
	fmt.Println("ASDF Closing...")
	p.S.Close()
}

func createMetricsConsumer(hostName string, port int, settings component.TelemetrySettings, otelVersion string) (*metricsConsumer, error) {
	s, err := senders.NewProxySender(&senders.ProxyConfiguration{
		Host:                 hostName,
		MetricsPort:          port,
		FlushIntervalSeconds: 1,
		SDKMetricsTags:       map[string]string{"otel.metrics.collector_version": otelVersion},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy sender: %v", err)
	}
	ps := &printSender{S: s}
	cumulative := newCumulativeHistogramDataPointConsumer(ps)
	delta := newDeltaHistogramDataPointConsumer(ps)
	return newMetricsConsumer(
		[]typedMetricConsumer{
			newGaugeConsumer(ps, settings),
			newSumConsumer(ps, settings),
			newHistogramConsumer(cumulative, delta, ps, regularHistogram, settings),
			newHistogramConsumer(cumulative, delta, ps, exponentialHistogram, settings),
			newSummaryConsumer(ps, settings),
		},
		ps,
		true), nil
}

type metricsConsumerCreator func(hostName string, port int, settings component.TelemetrySettings, otelVersion string) (
	*metricsConsumer, error)

func newMetricsExporter(settings component.ExporterCreateSettings, c config.Exporter, creator metricsConsumerCreator) (*metricsExporter, error) {
	cfg := c.(*Config)
	hostName, port := cfg.metricsHostNameAndPort()
	consumer, err := creator(hostName, port, settings.TelemetrySettings, settings.BuildInfo.Version)
	if err != nil {
		return nil, err
	}
	return &metricsExporter{
		consumer: consumer,
	}, nil
}

func (e *metricsExporter) pushMetricsData(ctx context.Context, md pdata.Metrics) error {
	fmt.Println("JKL preparing to send metrics")
	return e.consumer.Consume(ctx, md)
}

func (e *metricsExporter) shutdown(_ context.Context) error {
	e.consumer.Close()
	return nil
}
