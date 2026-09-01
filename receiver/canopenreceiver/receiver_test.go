package canopenreceiver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/metadata"
)

// fakeBusDialer adapts a *cantransport.FakeBus (whose Dial signature already
// matches cantransport.Dialer) for use as the receiver's dialer in tests.
type fakeBusDialer struct {
	bus *cantransport.FakeBus
}

func (d fakeBusDialer) Dial(ctx context.Context, iface string) (cantransport.Conn, error) {
	return d.bus.Dial(ctx, iface)
}

func TestReceiver_EndToEnd_SniffPDOAndEMCY(t *testing.T) {
	bus := cantransport.NewFakeBus()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 50 * time.Millisecond
	cfg.Metrics.FlushInterval = 100 * time.Millisecond
	cfg.Sniff.Enabled = true
	cfg.Sniff.EMCY.Emit = EmitLogs
	cfg.Sniff.PDOs = []PDOConfig{
		{
			Name:  "motor_tpdo1",
			CobID: 0x181,
			Signals: []SignalConfig{
				{Name: "canopen.motor.speed", Type: codec.Int16, Scale: 0.1, Emit: EmitMetrics},
			},
		},
	}
	require.NoError(t, cfg.Validate())

	set := receivertest.NewNopSettings(metadata.Type)
	r := newCanopenReceiver(cfg, set, fakeBusDialer{bus: bus})

	metricsSink := new(consumertest.MetricsSink)
	logsSink := new(consumertest.LogsSink)
	r.metricsConsumer = metricsSink
	r.logsConsumer = logsSink

	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, r.Shutdown(context.Background())) }()

	// Inject a PDO frame: int16 le 1234 -> bytes D2 04
	bus.Inject(cantransport.Frame{ID: 0x181, Data: []byte{0xD2, 0x04}})
	// Inject an EMCY frame for node 7: code 0x1000 (generic error), register 0x01
	bus.Inject(cantransport.Frame{ID: 0x87, Data: []byte{0x00, 0x10, 0x01, 0, 0, 0, 0, 0}})

	require.Eventually(t, func() bool {
		return len(metricsSink.AllMetrics()) > 0 && len(logsSink.AllLogs()) > 0
	}, 3*time.Second, 20*time.Millisecond)

	md := metricsSink.AllMetrics()[0]
	m := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "canopen.motor.speed", m.Name())
	assert.InDelta(t, 123.4, m.Gauge().DataPoints().At(0).DoubleValue(), 0.01)

	ld := logsSink.AllLogs()[0]
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Contains(t, lr.Body().Str(), "emergency")
}
