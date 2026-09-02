package canopenreceiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/metadata"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	assert.Equal(t, metadata.Type, f.Type())

	cfg := f.CreateDefaultConfig().(*Config)
	assert.Equal(t, MetricsConfig{Enabled: true, FlushInterval: cfg.Metrics.FlushInterval}, cfg.Metrics)
}

func TestFactory_CreateMetricsAndLogsReceiver_ShareInstance(t *testing.T) {
	f := NewFactory()
	cfg := validBaseConfig()

	set := receivertest.NewNopSettings(metadata.Type)
	mr, err := f.CreateMetrics(context.Background(), set, cfg, consumertest.NewNop())
	require.NoError(t, err)
	lr, err := f.CreateLogs(context.Background(), set, cfg, consumertest.NewNop())
	require.NoError(t, err)

	// Both should be backed by the same canopenReceiver instance since they
	// share a component ID, so they use one CAN connection.
	assert.Same(t, mr, lr)

	delete(sharedReceivers, instanceKey{id: set.ID})
}
