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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/exporter/exporterhelper"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
)

type TracesConfig struct {
	confighttp.HTTPClientSettings `mapstructure:",squash"` // squash ensures fields are correctly decoded in embedded struct.
}

type MetricsConfig struct {
	confighttp.HTTPClientSettings `mapstructure:",squash"`
	ResourceAttributes            resourcetotelemetry.Settings `mapstructure:"resource_attributes"`
}

// Config defines configuration options for the exporter.
type Config struct {
	config.ExporterSettings      `mapstructure:",squash"` // squash ensures fields are correctly decoded in embedded struct.
	exporterhelper.QueueSettings `mapstructure:"sending_queue"`
	exporterhelper.RetrySettings `mapstructure:"retry_on_failure"`

	// Traces defines the Traces exporter specific configuration
	Traces  *TracesConfig  `mapstructure:"traces"`
	Metrics *MetricsConfig `mapstructure:"metrics"`
}

// withoutMissingFields fills in the Metrics or Traces field of this instance if it is missing.
// withoutMissingFields returns a new Config instance with missing fields filled in while leaving c
// unchanged.
func (c *Config) withoutMissingFields() (filledIn Config, err error) {
	if c.Traces == nil && c.Metrics == nil {
		return Config{}, errors.New("either the traces or metrics stanza must be present")
	}
	filledIn = *c
	var tracesURL, metricsURL *url.URL
	if filledIn.Metrics == nil {
		tracesURL, err = parseEndpoint("traces", filledIn.Traces.Endpoint)
		if err != nil {
			return Config{}, err
		}
		metricsURL = &url.URL{}
		*metricsURL = *tracesURL
		metricsURL.Host = hostWithPort(tracesURL.Host, 2878)
		filledIn.Metrics = &MetricsConfig{HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: metricsURL.String()}}
	} else if filledIn.Traces == nil {
		metricsURL, err = parseEndpoint("metrics", filledIn.Metrics.Endpoint)
		if err != nil {
			return Config{}, err
		}
		tracesURL = &url.URL{}
		*tracesURL = *metricsURL
		tracesURL.Host = hostWithPort(metricsURL.Host, 30001)
		filledIn.Traces = &TracesConfig{HTTPClientSettings: confighttp.HTTPClientSettings{Endpoint: tracesURL.String()}}
	} else {
		metricsURL, err = parseEndpoint("metrics", filledIn.Metrics.Endpoint)
		if err != nil {
			return Config{}, err
		}
		tracesURL, err = parseEndpoint("traces", filledIn.Traces.Endpoint)
		if err != nil {
			return Config{}, err
		}
		if tracesURL.Hostname() != metricsURL.Hostname() {
			return Config{}, errors.New("host for metrics and traces must be the same")
		}
	}
	return
}

// sanitize changes this Config in place by filling in missing fields. If sanitize encounters an error,
// it leaves this Config unchanged.
func (c *Config) sanitize() error {
	cfg, err := c.withoutMissingFields()
	if err != nil {
		return err
	}
	*c = cfg
	return nil
}

// metricsHostNameAndPort returns the host name and port of the metrics endpoint.
// metricsHostNameAndPort panics if it can't extract the host name and port.
// Therefore, it should only be called after a successful call to sanitize(),
// which guarantees a valid host name and port for the metrics endpoint.
func (c *Config) metricsHostNameAndPort() (hostName string, port int) {
	return hostNameAndPort(c.Metrics.Endpoint)
}

// tracesHostNameAndPort returns the host name and port of the traces endpoint.
// metricsHostNameAndPort panics if it can't extract the host name and port.
// Therefore, it should only be called after a successful call to sanitize(),
// which guarantees a valid host name and port for the traces endpoint.
func (c *Config) tracesHostNameAndPort() (hostName string, port int) {
	return hostNameAndPort(c.Traces.Endpoint)
}

func hostNameAndPort(endpoint string) (hostName string, port int) {
	u, err := url.Parse(endpoint)
	if err != nil {
		panic(err)
	}
	hostName = u.Hostname()
	port, err = strconv.Atoi(u.Port())
	if err != nil {
		panic(err)
	}
	return
}

func hostWithPort(hostPort string, port int) string {
	host := extractHost(hostPort)
	return fmt.Sprintf("%s:%d", host, port)
}

func extractHost(hostPort string) string {
	colon := strings.LastIndexByte(hostPort, ':')
	if colon != -1 {
		return hostPort[:colon]
	}
	return hostPort
}

// Validate validates this config leaving it unchanged.
func (c *Config) Validate() error {
	_, err := c.withoutMissingFields()
	return err
}

func parseEndpoint(name string, endpoint string) (*url.URL, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("A non-empty %s.endpoint is required", name)
	}
	if !(strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://")) {
		return nil, fmt.Errorf("%s.endpoint must start with http:// or https://", name)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid %s.endpoint %s", name, err)
	}
	if _, err := strconv.Atoi(u.Port()); err != nil {
		return nil, fmt.Errorf("%s.endpoint requires a port", name)
	}
	return u, nil
}
