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

package tanzuobservabilityexporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/confighttp"
)

func TestConfigRequiresNonEmptyEndpoint(t *testing.T) {
	c := &Config{
		ExporterSettings: config.ExporterSettings{},
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: ""},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:2878"},
		},
	}

	assert.Error(t, c.Validate())
}

func TestConfigRequiresHttp(t *testing.T) {
	c := &Config{
		ExporterSettings: config.ExporterSettings{},
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "localhost:30001"},
		},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http")
	assert.Contains(t, err.Error(), "traces")
}

func TestConfigRequiresValidEndpointUrl(t *testing.T) {
	c := &Config{
		ExporterSettings: config.ExporterSettings{},
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http#$%^&#$%&#"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:2878"},
		},
	}

	assert.Error(t, c.Validate())
}

func TestMetricsConfigRequiresNonEmptyEndpoint(t *testing.T) {
	c := &Config{
		ExporterSettings: config.ExporterSettings{},
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:30001"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: ""},
		},
	}

	assert.Error(t, c.Validate())
}

func TestMetricsConfigRequiresValidEndpointUrl(t *testing.T) {
	c := &Config{
		ExporterSettings: config.ExporterSettings{},
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:30001"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http#$%^&#$%&#"},
		},
	}

	assert.Error(t, c.Validate())
}

func TestDifferentHostNames(t *testing.T) {
	c := &Config{
		ExporterSettings: config.ExporterSettings{},
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:30001"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://foo.com:2878"},
		},
	}
	assert.Error(t, c.Validate())
}

func TestTracesOnly(t *testing.T) {
	c := &Config{
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:40001"},
		},
	}
	assert.NoError(t, c.Validate())
}

func TestMetricsOnly(t *testing.T) {
	c := &Config{
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.10.10.10:2878"},
		},
	}
	assert.NoError(t, c.Validate())
}

func TestConfigNormal(t *testing.T) {
	c := &Config{
		ExporterSettings: config.ExporterSettings{},
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:40001"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://localhost:2916"},
		},
	}
	assert.NoError(t, c.Validate())
}

func TestSanitize_Nothing(t *testing.T) {
	c := &Config{}
	assert.Error(t, c.sanitize())
}

func TestSanitize_JustTraces(t *testing.T) {
	c := &Config{
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.0.1:40001"},
		},
	}
	require.NoError(t, c.sanitize())
	require.NotNil(t, c.Metrics)
	assert.Equal(t, "http://10.0.0.1:2878", c.Metrics.Endpoint)
	assert.Equal(t, "http://10.0.0.1:40001", c.Traces.Endpoint)
}

func TestSanitize_JustTracesBadURL(t *testing.T) {
	c := &Config{
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://#$%^&#$%&#:2145"},
		},
	}
	assert.Error(t, c.sanitize())
}

func TestSanitize_JustTracesBadPort(t *testing.T) {
	c := &Config{
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.0.1:abcd"},
		},
	}
	assert.Error(t, c.sanitize())
}

func TestSanitize_JustMetrics(t *testing.T) {
	c := &Config{
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.0.1:3878"},
		},
	}
	require.NoError(t, c.sanitize())
	require.NotNil(t, c.Traces)
	assert.Equal(t, "http://10.0.0.1:30001", c.Traces.Endpoint)
	assert.Equal(t, "http://10.0.0.1:3878", c.Metrics.Endpoint)
}

func TestSanitize_JustMetricsBadURL(t *testing.T) {
	c := &Config{
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://#$%^&#$%&#:2145"},
		},
	}
	assert.Error(t, c.sanitize())
}

func TestSanitize_JustMetricsBadPort(t *testing.T) {
	c := &Config{
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.0.1:abcd"},
		},
	}
	assert.Error(t, c.sanitize())
}

func TestSanitize_AllThere(t *testing.T) {
	c := &Config{
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.0.1:40001"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.0.1:3878"},
		},
	}
	require.NoError(t, c.sanitize())
	assert.Equal(t, "http://10.0.0.1:40001", c.Traces.Endpoint)
	assert.Equal(t, "http://10.0.0.1:3878", c.Metrics.Endpoint)
}

func TestSanitize_DifferentHostNames(t *testing.T) {
	c := &Config{
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.0.1:40001"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.10.0:3878"},
		},
	}
	assert.Error(t, c.sanitize())
}

func TestHostNameAndPort(t *testing.T) {
	c := &Config{
		Traces: &TracesConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.1.2:40001"},
		},
		Metrics: &MetricsConfig{
			HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: "http://10.0.1.2:3878"},
		},
	}
	hostName, port := c.tracesHostNameAndPort()
	assert.Equal(t, "10.0.1.2", hostName)
	assert.Equal(t, 40001, port)
	hostName, port = c.metricsHostNameAndPort()
	assert.Equal(t, "10.0.1.2", hostName)
	assert.Equal(t, 3878, port)
}
