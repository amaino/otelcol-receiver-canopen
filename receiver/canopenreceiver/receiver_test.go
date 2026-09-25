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
	cfg.Sniff.EMCY.Logs = true
	cfg.Sniff.PDOs = []PDOConfig{
		{
			Name:  "motor_tpdo1",
			CobID: 0x181,
			Signals: []SignalConfig{
				{Name: "canopen.motor.speed", Type: codec.Int16, Scale: 0.1, Metrics: true},
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

func TestReceiver_SDOUploadPollOnce(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.Metrics.FlushInterval = 20 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.Logs.Enabled = true
	cfg.Sniff.SDO.Channels = []SDOChannelConfig{{
		NodeID: 1, ClientToServerCobID: 0x601, ServerToClientCobID: 0x581,
	}}
	cfg.Sniff.SDO.Poll = SDOPollConfig{
		Mode:    "once",
		Timeout: time.Second,
		Objects: []SDOObjectConfig{{
			NodeID: 1, Index: 0x2001, SubIndex: 0,
			SignalConfig: SignalConfig{Name: "device.value", Type: codec.Uint16, Logs: true},
		}},
	}
	require.NoError(t, cfg.Validate())

	set := receivertest.NewNopSettings(metadata.Type)
	r := newCanopenReceiver(cfg, set, fakeBusDialer{bus: bus})
	logsSink := new(consumertest.LogsSink)
	r.logsConsumer = logsSink
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, r.Shutdown(context.Background())) }()

	recvCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request, err := monitor.Recv(recvCtx)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x601), request.ID)
	assert.Equal(t, []byte{0x40, 0x01, 0x20, 0, 0, 0, 0, 0}, request.Data)

	bus.Inject(cantransport.Frame{ID: 0x581, Data: []byte{0x4B, 0x01, 0x20, 0, 0x34, 0x12, 0, 0}})
	require.Eventually(t, func() bool { return len(logsSink.AllLogs()) > 0 }, time.Second, 10*time.Millisecond)
	log := logsSink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Contains(t, log.Body().Str(), "device.value")
}

func TestReceiver_SDOUploadPollSegmented(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.Metrics.FlushInterval = 20 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.Sniff.SDO.Poll = SDOPollConfig{
		Mode:    "once",
		Timeout: time.Second,
		Objects: []SDOObjectConfig{{
			NodeID: 1, Index: 0x2001, SubIndex: 0,
			SignalConfig: SignalConfig{Name: "device.text", Type: codec.VisibleString, ByteLen: 11, Logs: true},
		}},
	}
	require.NoError(t, cfg.Validate())

	set := receivertest.NewNopSettings(metadata.Type)
	r := newCanopenReceiver(cfg, set, fakeBusDialer{bus: bus})
	logsSink := new(consumertest.LogsSink)
	r.logsConsumer = logsSink
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, r.Shutdown(context.Background())) }()

	recvCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waitForData := func(expected []byte) {
		t.Helper()
		for {
			frame, receiveErr := monitor.Recv(recvCtx)
			require.NoError(t, receiveErr)
			if assert.ObjectsAreEqual(expected, frame.Data) {
				return
			}
		}
	}
	request, err := monitor.Recv(recvCtx)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x40, 0x01, 0x20, 0, 0, 0, 0, 0}, request.Data)

	bus.Inject(cantransport.Frame{ID: 0x581, Data: []byte{0x41, 0x01, 0x20, 0, 0x0B, 0, 0, 0}})
	waitForData([]byte{0x60, 0, 0, 0, 0, 0, 0, 0})

	bus.Inject(cantransport.Frame{ID: 0x581, Data: []byte{0x00, 'h', 'e', 'l', 'l', 'o', ' ', 'w'}})
	waitForData([]byte{0x70, 0, 0, 0, 0, 0, 0, 0})
	bus.Inject(cantransport.Frame{ID: 0x581, Data: []byte{0x17, 'o', 'r', 'l', 'd', 0, 0, 0}})

	require.Eventually(t, func() bool { return len(logsSink.AllLogs()) > 0 }, time.Second, 10*time.Millisecond)
	log := logsSink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Contains(t, log.Body().Str(), "device.text")
}
