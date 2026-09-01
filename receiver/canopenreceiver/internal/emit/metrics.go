// Package emit builds OpenTelemetry metrics and logs payloads from decoded
// CANopen signal values.
package emit

import (
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/metadata"
)

// MetricKind selects the OTel metric data point type.
type MetricKind int

const (
	KindGauge MetricKind = iota
	KindSum
)

// MetricPoint is one decoded signal value ready to be appended to a metrics
// batch.
type MetricPoint struct {
	// ResourceAttrs identify the CAN interface/node this value came from
	// (e.g. "canopen.interface", "canopen.node_id").
	ResourceAttrs map[string]string
	Name          string
	Unit          string
	Kind          MetricKind
	Value         float64
	Attributes    map[string]string
	Timestamp     time.Time
}

// MetricsBuilder accumulates MetricPoints into a pmetric.Metrics batch,
// grouping data points under one ResourceMetrics per distinct ResourceAttrs
// set and one Metric per distinct name within that resource.
type MetricsBuilder struct {
	resources map[string]pmetric.ResourceMetrics
	metrics   map[string]map[string]pmetric.Metric // resourceKey -> metric name -> Metric
	md        pmetric.Metrics
}

// NewMetricsBuilder creates an empty MetricsBuilder.
func NewMetricsBuilder() *MetricsBuilder {
	return &MetricsBuilder{
		resources: make(map[string]pmetric.ResourceMetrics),
		metrics:   make(map[string]map[string]pmetric.Metric),
		md:        pmetric.NewMetrics(),
	}
}

func resourceKey(attrs map[string]string) string {
	// Deterministic-enough key for the small, fixed attribute sets this
	// receiver uses (interface, optionally node_id).
	key := ""
	for _, k := range []string{"canopen.interface", "canopen.node_id"} {
		if v, ok := attrs[k]; ok {
			key += k + "=" + v + ";"
		}
	}
	return key
}

func (b *MetricsBuilder) resourceMetrics(attrs map[string]string) (pmetric.ResourceMetrics, map[string]pmetric.Metric) {
	key := resourceKey(attrs)
	if rm, ok := b.resources[key]; ok {
		return rm, b.metrics[key]
	}
	rm := b.md.ResourceMetrics().AppendEmpty()
	res := rm.Resource()
	for k, v := range attrs {
		res.Attributes().PutStr(k, v)
	}
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(metadata.ScopeName)
	b.resources[key] = rm
	b.metrics[key] = make(map[string]pmetric.Metric)
	return rm, b.metrics[key]
}

// Add appends a single decoded value as a data point.
func (b *MetricsBuilder) Add(p MetricPoint) {
	rm, metrics := b.resourceMetrics(p.ResourceAttrs)
	m, ok := metrics[p.Name]
	if !ok {
		sm := rm.ScopeMetrics().At(0)
		m = sm.Metrics().AppendEmpty()
		m.SetName(p.Name)
		m.SetUnit(p.Unit)
		switch p.Kind {
		case KindSum:
			sum := m.SetEmptySum()
			sum.SetIsMonotonic(false)
			sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		default:
			m.SetEmptyGauge()
		}
		metrics[p.Name] = m
	}

	ts := p.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	var dp pmetric.NumberDataPoint
	if p.Kind == KindSum {
		dp = m.Sum().DataPoints().AppendEmpty()
	} else {
		dp = m.Gauge().DataPoints().AppendEmpty()
	}
	dp.SetTimestamp(pcommon.NewTimestampFromTime(ts))
	dp.SetDoubleValue(p.Value)
	for k, v := range p.Attributes {
		dp.Attributes().PutStr(k, v)
	}
}

// Empty reports whether no data points have been added since the last Emit.
func (b *MetricsBuilder) Empty() bool {
	return b.md.ResourceMetrics().Len() == 0
}

// Emit returns the accumulated batch and resets the builder for the next
// interval.
func (b *MetricsBuilder) Emit() pmetric.Metrics {
	out := b.md
	b.md = pmetric.NewMetrics()
	b.resources = make(map[string]pmetric.ResourceMetrics)
	b.metrics = make(map[string]map[string]pmetric.Metric)
	return out
}
