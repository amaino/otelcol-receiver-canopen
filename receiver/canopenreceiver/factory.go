package canopenreceiver

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/metadata"
)

// instanceKey identifies a shared canopenReceiver instance per unique
// component ID within one collector build, so metrics and logs pipelines
// referencing the same receiver instance name share one CAN connection.
type instanceKey struct {
	id component.ID
}

// sharedReceivers holds in-flight instances keyed by component ID so the
// metrics and logs factory functions can return the same underlying
// canopenReceiver when both signals are configured for one receiver
// instance.
var sharedReceivers = map[instanceKey]*canopenReceiver{}

// NewFactory creates a factory for the CANopen receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithMetrics(createMetricsReceiver, metadata.MetricsStability),
		receiver.WithLogs(createLogsReceiver, metadata.LogsStability),
	)
}

func getOrCreateReceiver(set receiver.Settings, cfg *Config) *canopenReceiver {
	key := instanceKey{id: set.ID}
	if r, ok := sharedReceivers[key]; ok {
		return r
	}
	r := newCanopenReceiver(cfg, set, cantransport.NewDialer())
	sharedReceivers[key] = r
	return r
}

func createMetricsReceiver(
	_ context.Context,
	set receiver.Settings,
	rawCfg component.Config,
	next consumer.Metrics,
) (receiver.Metrics, error) {
	cfg, ok := rawCfg.(*Config)
	if !ok {
		return nil, errors.New("canopenreceiver: invalid config type")
	}
	r := getOrCreateReceiver(set, cfg)
	r.metricsConsumer = next
	return r, nil
}

func createLogsReceiver(
	_ context.Context,
	set receiver.Settings,
	rawCfg component.Config,
	next consumer.Logs,
) (receiver.Logs, error) {
	cfg, ok := rawCfg.(*Config)
	if !ok {
		return nil, errors.New("canopenreceiver: invalid config type")
	}
	r := getOrCreateReceiver(set, cfg)
	r.logsConsumer = next
	return r, nil
}
