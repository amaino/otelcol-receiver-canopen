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
	Body          string
	Attributes    map[string]any
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
	lr.Body().SetStr(r.Body)
	for k, v := range r.Attributes {
		switch val := v.(type) {
		case string:
			lr.Attributes().PutStr(k, val)
		case int:
			lr.Attributes().PutInt(k, int64(val))
		case int64:
			lr.Attributes().PutInt(k, val)
		case uint8:
			lr.Attributes().PutInt(k, int64(val))
		case uint16:
			lr.Attributes().PutInt(k, int64(val))
		case uint32:
			lr.Attributes().PutInt(k, int64(val))
		case uint64:
			lr.Attributes().PutInt(k, int64(val))
		case float64:
			lr.Attributes().PutDouble(k, val)
		case bool:
			lr.Attributes().PutBool(k, val)
		default:
			lr.Attributes().PutStr(k, "")
		}
	}
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
