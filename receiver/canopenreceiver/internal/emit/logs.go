package emit

import (
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/metadata"
)

// LogRecord is one event ready to be appended to a logs batch: a decoded
// signal configured for log emission, an EMCY emergency message, an NMT
// state change.
type LogRecord struct {
	ResourceAttrs map[string]string
	Timestamp     time.Time
	Severity      plog.SeverityNumber
	// Body is a plain-text body, used when BodyValue and BodyMap are nil.
	Body string
	// BodyValue is a scalar structured body for a single decoded field.
	BodyValue any
	// BodyMap, when non-nil, is used as a structured map body - one entry per
	// decoded field name/value, matching how the
	// rest of the OTel Collector ecosystem represents parsed structured
	// data (map body), keeping Attributes reserved for record metadata.
	BodyMap    map[string]any
	Attributes map[string]any
}

// LogsBuilder accumulates LogRecords into a plog.Logs batch, grouping
// records under one ResourceLogs per distinct ResourceAttrs set.
type LogsBuilder struct {
	resources map[string]plog.ResourceLogs
	scopes    map[string]plog.ScopeLogs
	ld        plog.Logs
}

// NewLogsBuilder creates an empty LogsBuilder.
func NewLogsBuilder() *LogsBuilder {
	return &LogsBuilder{
		resources: make(map[string]plog.ResourceLogs),
		scopes:    make(map[string]plog.ScopeLogs),
		ld:        plog.NewLogs(),
	}
}

func (b *LogsBuilder) scopeLogs(attrs map[string]string) plog.ScopeLogs {
	key := resourceKey(attrs)
	if sl, ok := b.scopes[key]; ok {
		return sl
	}
	rl := b.ld.ResourceLogs().AppendEmpty()
	res := rl.Resource()
	for k, v := range attrs {
		res.Attributes().PutStr(k, v)
	}
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(metadata.ScopeName)
	b.resources[key] = rl
	b.scopes[key] = sl
	return sl
}

// Add appends a single log record.
func (b *LogsBuilder) Add(r LogRecord) {
	sl := b.scopeLogs(r.ResourceAttrs)
	lr := sl.LogRecords().AppendEmpty()
	ts := r.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	lr.SetTimestamp(pcommon.NewTimestampFromTime(ts))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	lr.SetSeverityNumber(r.Severity)
	lr.SetSeverityText(r.Severity.String())
	if r.BodyValue != nil {
		_ = lr.Body().FromRaw(r.BodyValue)
	} else if r.BodyMap != nil {
		// Config validation (see canopenreceiver.validateStaticAttributes)
		// already guarantees every value is a type pcommon.Map.FromRaw
		// supports, so no error handling is needed here.
		_ = lr.Body().SetEmptyMap().FromRaw(r.BodyMap)
	} else {
		lr.Body().SetStr(r.Body)
	}
	// Config validation (see canopenreceiver.validateStaticAttributes)
	// already guarantees every attribute value is a type pcommon.Map.FromRaw
	// supports, so no error handling is needed here.
	_ = lr.Attributes().FromRaw(r.Attributes)
}

// Empty reports whether no records have been added since the last Emit.
func (b *LogsBuilder) Empty() bool {
	return b.ld.ResourceLogs().Len() == 0
}

// Emit returns the accumulated batch and resets the builder.
func (b *LogsBuilder) Emit() plog.Logs {
	out := b.ld
	b.ld = plog.NewLogs()
	b.resources = make(map[string]plog.ResourceLogs)
	b.scopes = make(map[string]plog.ScopeLogs)
	return out
}
