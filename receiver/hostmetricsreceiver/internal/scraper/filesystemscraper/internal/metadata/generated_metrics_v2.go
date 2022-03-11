// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"time"

	"go.opentelemetry.io/collector/model/pdata"
)

// MetricSettings provides common settings for a particular metric.
type MetricSettings struct {
	Enabled bool `mapstructure:"enabled"`
}

// MetricsSettings provides settings for hostmetricsreceiver/filesystem metrics.
type MetricsSettings struct {
	SystemFilesystemInodesUsage MetricSettings `mapstructure:"system.filesystem.inodes.usage"`
	SystemFilesystemUsage       MetricSettings `mapstructure:"system.filesystem.usage"`
	SystemFilesystemUtilization MetricSettings `mapstructure:"system.filesystem.utilization"`
}

func DefaultMetricsSettings() MetricsSettings {
	return MetricsSettings{
		SystemFilesystemInodesUsage: MetricSettings{
			Enabled: true,
		},
		SystemFilesystemUsage: MetricSettings{
			Enabled: true,
		},
		SystemFilesystemUtilization: MetricSettings{
			Enabled: false,
		},
	}
}

type metricSystemFilesystemInodesUsage struct {
	data     pdata.Metric   // data buffer for generated metric.
	settings MetricSettings // metric settings provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills system.filesystem.inodes.usage metric with initial data.
func (m *metricSystemFilesystemInodesUsage) init() {
	m.data.SetName("system.filesystem.inodes.usage")
	m.data.SetDescription("FileSystem inodes used.")
	m.data.SetUnit("{inodes}")
	m.data.SetDataType(pdata.MetricDataTypeSum)
	m.data.Sum().SetIsMonotonic(false)
	m.data.Sum().SetAggregationTemporality(pdata.MetricAggregationTemporalityCumulative)
	m.data.Sum().DataPoints().EnsureCapacity(m.capacity)
}

func (m *metricSystemFilesystemInodesUsage) recordDataPoint(start pdata.Timestamp, ts pdata.Timestamp, val int64, deviceAttributeValue string, modeAttributeValue string, mountpointAttributeValue string, typeAttributeValue string, stateAttributeValue string) {
	if !m.settings.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntVal(val)
	dp.Attributes().Insert(A.Device, pdata.NewAttributeValueString(deviceAttributeValue))
	dp.Attributes().Insert(A.Mode, pdata.NewAttributeValueString(modeAttributeValue))
	dp.Attributes().Insert(A.Mountpoint, pdata.NewAttributeValueString(mountpointAttributeValue))
	dp.Attributes().Insert(A.Type, pdata.NewAttributeValueString(typeAttributeValue))
	dp.Attributes().Insert(A.State, pdata.NewAttributeValueString(stateAttributeValue))
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricSystemFilesystemInodesUsage) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricSystemFilesystemInodesUsage) emit(metrics pdata.MetricSlice) {
	if m.settings.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricSystemFilesystemInodesUsage(settings MetricSettings) metricSystemFilesystemInodesUsage {
	m := metricSystemFilesystemInodesUsage{settings: settings}
	if settings.Enabled {
		m.data = pdata.NewMetric()
		m.init()
	}
	return m
}

type metricSystemFilesystemUsage struct {
	data     pdata.Metric   // data buffer for generated metric.
	settings MetricSettings // metric settings provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills system.filesystem.usage metric with initial data.
func (m *metricSystemFilesystemUsage) init() {
	m.data.SetName("system.filesystem.usage")
	m.data.SetDescription("Filesystem bytes used.")
	m.data.SetUnit("By")
	m.data.SetDataType(pdata.MetricDataTypeSum)
	m.data.Sum().SetIsMonotonic(false)
	m.data.Sum().SetAggregationTemporality(pdata.MetricAggregationTemporalityCumulative)
	m.data.Sum().DataPoints().EnsureCapacity(m.capacity)
}

func (m *metricSystemFilesystemUsage) recordDataPoint(start pdata.Timestamp, ts pdata.Timestamp, val int64, deviceAttributeValue string, modeAttributeValue string, mountpointAttributeValue string, typeAttributeValue string, stateAttributeValue string) {
	if !m.settings.Enabled {
		return
	}
	dp := m.data.Sum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetIntVal(val)
	dp.Attributes().Insert(A.Device, pdata.NewAttributeValueString(deviceAttributeValue))
	dp.Attributes().Insert(A.Mode, pdata.NewAttributeValueString(modeAttributeValue))
	dp.Attributes().Insert(A.Mountpoint, pdata.NewAttributeValueString(mountpointAttributeValue))
	dp.Attributes().Insert(A.Type, pdata.NewAttributeValueString(typeAttributeValue))
	dp.Attributes().Insert(A.State, pdata.NewAttributeValueString(stateAttributeValue))
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricSystemFilesystemUsage) updateCapacity() {
	if m.data.Sum().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Sum().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricSystemFilesystemUsage) emit(metrics pdata.MetricSlice) {
	if m.settings.Enabled && m.data.Sum().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricSystemFilesystemUsage(settings MetricSettings) metricSystemFilesystemUsage {
	m := metricSystemFilesystemUsage{settings: settings}
	if settings.Enabled {
		m.data = pdata.NewMetric()
		m.init()
	}
	return m
}

type metricSystemFilesystemUtilization struct {
	data     pdata.Metric   // data buffer for generated metric.
	settings MetricSettings // metric settings provided by user.
	capacity int            // max observed number of data points added to the metric.
}

// init fills system.filesystem.utilization metric with initial data.
func (m *metricSystemFilesystemUtilization) init() {
	m.data.SetName("system.filesystem.utilization")
	m.data.SetDescription("Fraction of filesystem bytes used.")
	m.data.SetUnit("1")
	m.data.SetDataType(pdata.MetricDataTypeGauge)
	m.data.Gauge().DataPoints().EnsureCapacity(m.capacity)
}

func (m *metricSystemFilesystemUtilization) recordDataPoint(start pdata.Timestamp, ts pdata.Timestamp, val float64, deviceAttributeValue string, modeAttributeValue string, mountpointAttributeValue string, typeAttributeValue string) {
	if !m.settings.Enabled {
		return
	}
	dp := m.data.Gauge().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(start)
	dp.SetTimestamp(ts)
	dp.SetDoubleVal(val)
	dp.Attributes().Insert(A.Device, pdata.NewAttributeValueString(deviceAttributeValue))
	dp.Attributes().Insert(A.Mode, pdata.NewAttributeValueString(modeAttributeValue))
	dp.Attributes().Insert(A.Mountpoint, pdata.NewAttributeValueString(mountpointAttributeValue))
	dp.Attributes().Insert(A.Type, pdata.NewAttributeValueString(typeAttributeValue))
}

// updateCapacity saves max length of data point slices that will be used for the slice capacity.
func (m *metricSystemFilesystemUtilization) updateCapacity() {
	if m.data.Gauge().DataPoints().Len() > m.capacity {
		m.capacity = m.data.Gauge().DataPoints().Len()
	}
}

// emit appends recorded metric data to a metrics slice and prepares it for recording another set of data points.
func (m *metricSystemFilesystemUtilization) emit(metrics pdata.MetricSlice) {
	if m.settings.Enabled && m.data.Gauge().DataPoints().Len() > 0 {
		m.updateCapacity()
		m.data.MoveTo(metrics.AppendEmpty())
		m.init()
	}
}

func newMetricSystemFilesystemUtilization(settings MetricSettings) metricSystemFilesystemUtilization {
	m := metricSystemFilesystemUtilization{settings: settings}
	if settings.Enabled {
		m.data = pdata.NewMetric()
		m.init()
	}
	return m
}

// MetricsBuilder provides an interface for scrapers to report metrics while taking care of all the transformations
// required to produce metric representation defined in metadata and user settings.
type MetricsBuilder struct {
	startTime                         pdata.Timestamp
	metricSystemFilesystemInodesUsage metricSystemFilesystemInodesUsage
	metricSystemFilesystemUsage       metricSystemFilesystemUsage
	metricSystemFilesystemUtilization metricSystemFilesystemUtilization
}

// metricBuilderOption applies changes to default metrics builder.
type metricBuilderOption func(*MetricsBuilder)

// WithStartTime sets startTime on the metrics builder.
func WithStartTime(startTime pdata.Timestamp) metricBuilderOption {
	return func(mb *MetricsBuilder) {
		mb.startTime = startTime
	}
}

func NewMetricsBuilder(settings MetricsSettings, options ...metricBuilderOption) *MetricsBuilder {
	mb := &MetricsBuilder{
		startTime:                         pdata.NewTimestampFromTime(time.Now()),
		metricSystemFilesystemInodesUsage: newMetricSystemFilesystemInodesUsage(settings.SystemFilesystemInodesUsage),
		metricSystemFilesystemUsage:       newMetricSystemFilesystemUsage(settings.SystemFilesystemUsage),
		metricSystemFilesystemUtilization: newMetricSystemFilesystemUtilization(settings.SystemFilesystemUtilization),
	}
	for _, op := range options {
		op(mb)
	}
	return mb
}

// Emit appends generated metrics to a pdata.MetricsSlice and updates the internal state to be ready for recording
// another set of data points. This function will be doing all transformations required to produce metric representation
// defined in metadata and user settings, e.g. delta/cumulative translation.
func (mb *MetricsBuilder) Emit(metrics pdata.MetricSlice) {
	mb.metricSystemFilesystemInodesUsage.emit(metrics)
	mb.metricSystemFilesystemUsage.emit(metrics)
	mb.metricSystemFilesystemUtilization.emit(metrics)
}

// RecordSystemFilesystemInodesUsageDataPoint adds a data point to system.filesystem.inodes.usage metric.
func (mb *MetricsBuilder) RecordSystemFilesystemInodesUsageDataPoint(ts pdata.Timestamp, val int64, deviceAttributeValue string, modeAttributeValue string, mountpointAttributeValue string, typeAttributeValue string, stateAttributeValue string) {
	mb.metricSystemFilesystemInodesUsage.recordDataPoint(mb.startTime, ts, val, deviceAttributeValue, modeAttributeValue, mountpointAttributeValue, typeAttributeValue, stateAttributeValue)
}

// RecordSystemFilesystemUsageDataPoint adds a data point to system.filesystem.usage metric.
func (mb *MetricsBuilder) RecordSystemFilesystemUsageDataPoint(ts pdata.Timestamp, val int64, deviceAttributeValue string, modeAttributeValue string, mountpointAttributeValue string, typeAttributeValue string, stateAttributeValue string) {
	mb.metricSystemFilesystemUsage.recordDataPoint(mb.startTime, ts, val, deviceAttributeValue, modeAttributeValue, mountpointAttributeValue, typeAttributeValue, stateAttributeValue)
}

// RecordSystemFilesystemUtilizationDataPoint adds a data point to system.filesystem.utilization metric.
func (mb *MetricsBuilder) RecordSystemFilesystemUtilizationDataPoint(ts pdata.Timestamp, val float64, deviceAttributeValue string, modeAttributeValue string, mountpointAttributeValue string, typeAttributeValue string) {
	mb.metricSystemFilesystemUtilization.recordDataPoint(mb.startTime, ts, val, deviceAttributeValue, modeAttributeValue, mountpointAttributeValue, typeAttributeValue)
}

// Reset resets metrics builder to its initial state. It should be used when external metrics source is restarted,
// and metrics builder should update its startTime and reset it's internal state accordingly.
func (mb *MetricsBuilder) Reset(options ...metricBuilderOption) {
	mb.startTime = pdata.NewTimestampFromTime(time.Now())
	for _, op := range options {
		op(mb)
	}
}

// NewMetricData creates new pdata.Metrics and sets the InstrumentationLibrary
// name on the ResourceMetrics.
func (mb *MetricsBuilder) NewMetricData() pdata.Metrics {
	md := pdata.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	ilm := rm.InstrumentationLibraryMetrics().AppendEmpty()
	ilm.InstrumentationLibrary().SetName("otelcol/hostmetricsreceiver/filesystem")
	return md
}

// Attributes contains the possible metric attributes that can be used.
var Attributes = struct {
	// Device (Identifier of the filesystem.)
	Device string
	// Mode (Mountpoint mode such "ro", "rw", etc.)
	Mode string
	// Mountpoint (Mountpoint path.)
	Mountpoint string
	// State (Breakdown of filesystem usage by type.)
	State string
	// Type (Filesystem type, such as, "ext4", "tmpfs", etc.)
	Type string
}{
	"device",
	"mode",
	"mountpoint",
	"state",
	"type",
}

// A is an alias for Attributes.
var A = Attributes

// AttributeState are the possible values that the attribute "state" can have.
var AttributeState = struct {
	Free     string
	Reserved string
	Used     string
}{
	"free",
	"reserved",
	"used",
}