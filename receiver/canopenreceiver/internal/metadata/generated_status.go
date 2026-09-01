// Package metadata provides component identity and stability information for the
// canopenreceiver, mirroring the structure produced by mdatagen in
// opentelemetry-collector-contrib so this package can be regenerated/replaced
// with a real mdatagen output when this receiver moves into contrib.
package metadata

import (
	"go.opentelemetry.io/collector/component"
)

var (
	// Type is the component type for this receiver.
	Type = component.MustNewType("canopen")
)

const (
	// MetricsStability is the stability level of the metrics signal.
	MetricsStability = component.StabilityLevelDevelopment
	// LogsStability is the stability level of the logs signal.
	LogsStability = component.StabilityLevelDevelopment
	// ScopeName is used as the instrumentation scope name for emitted telemetry.
	ScopeName = "github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver"
)
