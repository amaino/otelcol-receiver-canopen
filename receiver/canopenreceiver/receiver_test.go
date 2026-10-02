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
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

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
	cfg.EMCY.Logs = true
	cfg.PDO = []PDOConfig{
		{
			Name:  "motor_tpdo1",
			CobID: 0x181,
			Fields: []FieldConfig{
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

// Enabled signals are consumed independently for each decoded frame.
func TestReceiver_ConsumesEnabledSignals(t *testing.T) {
	tests := []struct {
		name           string
		metricsEnabled bool
		logsEnabled    bool
	}{
		{name: "both enabled", metricsEnabled: true, logsEnabled: true},
		{name: "metrics disabled", metricsEnabled: false, logsEnabled: true},
		{name: "logs disabled", metricsEnabled: true, logsEnabled: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := cantransport.NewFakeBus()

			cfg := createDefaultConfig().(*Config)
			cfg.Interface = "vcan0"
			cfg.ReadTimeout = 50 * time.Millisecond
			cfg.Metrics.Enabled = tt.metricsEnabled
			cfg.Logs.Enabled = tt.logsEnabled
			cfg.PDO = []PDOConfig{
				{
					Name:  "motor_tpdo1",
					CobID: 0x181,
					Fields: []FieldConfig{
						{Name: "canopen.motor.speed.metric", Type: codec.Int16, Scale: 0.1, Metrics: tt.metricsEnabled},
						{Name: "canopen.motor.speed.log", Type: codec.Int16, Scale: 0.1, Logs: tt.logsEnabled},
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

			// Wait only for enabled signals; disabled outputs must stay empty.
			if tt.metricsEnabled {
				require.Eventually(t, func() bool {
					return len(metricsSink.AllMetrics()) > 0
				}, 3*time.Second, 20*time.Millisecond)
			}
			if tt.logsEnabled {
				require.Eventually(t, func() bool {
					return len(logsSink.AllLogs()) > 0
				}, 3*time.Second, 20*time.Millisecond)
			}

			if tt.metricsEnabled {
				require.NotEmpty(t, metricsSink.AllMetrics())
			} else {
				assert.Empty(t, metricsSink.AllMetrics(), "metrics must not be emitted when metrics.enabled=false")
			}
			if tt.logsEnabled {
				require.NotEmpty(t, logsSink.AllLogs())
			} else {
				assert.Empty(t, logsSink.AllLogs(), "logs must not be emitted when logs.enabled=false")
			}
		})
	}
}
func TestReceiver_SDOUploadPollOnce(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.Logs.Enabled = true
	cfg.SDO.Sniff.Channels = []SDOChannelConfig{{
		NodeID: 1, ClientToServerCobID: 0x601, ServerToClientCobID: 0x581,
	}}
	cfg.SDO.Poll = SDOPollConfig{
		Mode:    "once",
		Timeout: time.Second,
		Objects: []SDOObjectConfig{{
			NodeID: 1, Index: 0x2001, SubIndex: 0,
			Fields: []FieldConfig{{Name: "device.value", Type: codec.Uint16, Logs: true}},
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
	assert.InDelta(t, float64(0x1234), log.Body().Double(), 0.001)
}

func TestReceiver_SDOUploadPollSegmented(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.SDO.Poll = SDOPollConfig{
		Mode:    "once",
		Timeout: time.Second,
		Objects: []SDOObjectConfig{{
			NodeID: 1, Index: 0x2001, SubIndex: 0,
			Fields: []FieldConfig{{Name: "device.text", Type: codec.VisibleString, ByteLen: 11, Logs: true}},
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
	assert.Equal(t, "hello world", log.Body().Str())
}

func TestReceiver_SDOUploadPollRetriesAfterAbort(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.SDO.Poll = SDOPollConfig{
		Mode:       "once",
		Timeout:    100 * time.Millisecond,
		Retry:      true,
		Backoff:    time.Millisecond,
		MaxBackoff: time.Millisecond,
		MaxRetries: intPointer(1),
		Objects: []SDOObjectConfig{{
			NodeID: 1, Index: 0x2001, SubIndex: 0,
			Fields: []FieldConfig{{Name: "device.value", Type: codec.Uint16}},
		}},
	}
	require.NoError(t, cfg.Validate())

	set := receivertest.NewNopSettings(metadata.Type)
	logCore, observedLogs := observer.New(zap.DebugLevel)
	set.Logger = zap.New(logCore)
	r := newCanopenReceiver(cfg, set, fakeBusDialer{bus: bus})
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, r.Shutdown(context.Background())) }()

	recvCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	firstRequest, err := monitor.Recv(recvCtx)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x601), firstRequest.ID)

	bus.Inject(cantransport.Frame{ID: 0x581, Data: []byte{0x80, 0x01, 0x20, 0, 0, 0, 0x02, 0x06}})
	waitForFrameData(t, recvCtx, monitor, firstRequest.Data)

	bus.Inject(cantransport.Frame{ID: 0x581, Data: []byte{0x4B, 0x01, 0x20, 0, 0x34, 0x12, 0, 0}})

	require.Eventually(t, func() bool {
		return len(observedLogs.FilterMessage("canopen: SDO poll recovered after retry").All()) == 1
	}, time.Second, 10*time.Millisecond)
	entries := observedLogs.All()
	require.Len(t, entries, 2)
	assert.Equal(t, "canopen: SDO poll attempt failed; retry scheduled", entries[0].Message)
	assert.Contains(t, entries[0].ContextMap()["error"], "SDO abort for 0x2001:00")
	assert.Equal(t, "canopen: SDO poll recovered after retry", entries[1].Message)
	assert.Equal(t, int64(2), entries[1].ContextMap()["attempts"])
}

func TestSDOPoller_IgnoresAbortForDifferentObject(t *testing.T) {
	active := &activeSDOPoll{
		object:      SDOObjectConfig{NodeID: 1, Index: 0x2001, SubIndex: 0},
		serverCobID: 0x581,
		result:      make(chan sdoPollResult, 1),
	}
	poller := &sdoPoller{active: active}

	poller.handleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x80, 0x02, 0x20, 0x00, 0, 0, 2, 6}})
	select {
	case result := <-active.result:
		t.Fatalf("unrelated abort completed active poll: %+v", result)
	default:
	}

	poller.handleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x80, 0x01, 0x20, 0x00, 0, 0, 2, 6}})
	select {
	case result := <-active.result:
		assert.False(t, result.ok)
	case <-time.After(time.Second):
		t.Fatal("matching abort did not complete active poll")
	}
}

func TestReceiver_SDOUploadPollTimeoutDoesNotEmitValue(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.Logs.Enabled = true
	cfg.SDO.Poll = SDOPollConfig{
		Mode:    "once",
		Timeout: 50 * time.Millisecond,
		Objects: []SDOObjectConfig{{
			NodeID: 1, Index: 0x2001, SubIndex: 0,
			Fields: []FieldConfig{{Name: "device.value", Type: codec.Uint16, Logs: true}},
		}},
	}
	require.NoError(t, cfg.Validate())

	set := receivertest.NewNopSettings(metadata.Type)
	logCore, observedLogs := observer.New(zap.DebugLevel)
	set.Logger = zap.New(logCore)
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

	require.Never(t, func() bool { return len(logsSink.AllLogs()) > 0 }, 200*time.Millisecond, 10*time.Millisecond)

	noReplyCtx, stopWaiting := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stopWaiting()
	_, err = monitor.Recv(noReplyCtx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	require.Eventually(t, func() bool {
		return len(observedLogs.FilterMessage("canopen: SDO poll failed; retries disabled").All()) == 1
	}, time.Second, 10*time.Millisecond)
	entries := observedLogs.FilterMessage("canopen: SDO poll failed; retries disabled").All()
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].ContextMap()["error"], "response timed out")
}

func TestReceiver_SDOUploadPollInterval(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.SDO.Poll = SDOPollConfig{
		Mode:     "interval",
		Interval: 30 * time.Millisecond,
		Timeout:  time.Second,
		Objects: []SDOObjectConfig{{
			NodeID: 1, Index: 0x2001, SubIndex: 0,
			Fields: []FieldConfig{{Name: "device.value", Type: codec.Uint16}},
		}},
	}
	require.NoError(t, cfg.Validate())

	set := receivertest.NewNopSettings(metadata.Type)
	r := newCanopenReceiver(cfg, set, fakeBusDialer{bus: bus})
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, r.Shutdown(context.Background())) }()

	recvCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	firstRequest, err := monitor.Recv(recvCtx)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x601), firstRequest.ID)
	bus.Inject(cantransport.Frame{ID: 0x581, Data: []byte{0x4B, 0x01, 0x20, 0, 0x34, 0x12, 0, 0}})

	waitForFrameData(t, recvCtx, monitor, firstRequest.Data)
}

func waitForFrameData(t *testing.T, ctx context.Context, conn cantransport.Conn, expected []byte) {
	t.Helper()
	for {
		frame, err := conn.Recv(ctx)
		require.NoError(t, err)
		if assert.ObjectsAreEqual(expected, frame.Data) {
			return
		}
	}
}

func intPointer(value int) *int {
	return &value
}

func TestReceiver_RawTransactionPoll(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 20 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.Raw.Transactions = []RawTransactionConfig{{
		Name:     "device.firmware",
		CobID:    0x51E,
		Payload:  []byte{0x08, 0x80},
		Timeout:  time.Second,
		Interval: time.Hour,
		Response: RawResponseConfig{
			CobID:  0x49E,
			Match:  []RawMatchByte{{ByteOffset: 0, Value: 0x08}, {ByteOffset: 1, Value: 0x80}},
			Fields: []FieldConfig{{Name: "device.version", BitOffset: 16, Type: codec.Uint32, Logs: true}},
		},
	}}
	cfg.Raw.Sniff.Logs = false
	cfg.Raw.Sniff.Messages = []RawMessageConfig{{
		Name:   "passive.firmware",
		CobID:  0x49E,
		Match:  []RawMatchByte{{ByteOffset: 0, Value: 0x08}, {ByteOffset: 1, Value: 0x80}},
		Fields: []FieldConfig{{Name: "passive.firmware", BitOffset: 16, Type: codec.Uint32, Logs: true}},
	}}
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
	assert.Equal(t, uint32(0x51E), request.ID)
	assert.Equal(t, []byte{0x08, 0x80}, request.Data)

	bus.Inject(cantransport.Frame{ID: 0x49E, Data: []byte{0x37, 0x80, 0x07, 0x04, 0, 0, 0, 0}})
	require.Never(t, func() bool { return len(logsSink.AllLogs()) > 0 }, 50*time.Millisecond, 5*time.Millisecond)
	bus.Inject(cantransport.Frame{ID: 0x49E, Data: []byte{0x08, 0x80, 0x78, 0x56, 0x34, 0x12, 0, 0}})
	require.Eventually(t, func() bool { return len(logsSink.AllLogs()) > 0 }, time.Second, 10*time.Millisecond)
	var recordCount int
	var transactionRecordFound bool
	for _, logData := range logsSink.AllLogs() {
		for resourceIndex := 0; resourceIndex < logData.ResourceLogs().Len(); resourceIndex++ {
			resourceLogs := logData.ResourceLogs().At(resourceIndex)
			for scopeIndex := 0; scopeIndex < resourceLogs.ScopeLogs().Len(); scopeIndex++ {
				records := resourceLogs.ScopeLogs().At(scopeIndex).LogRecords()
				recordCount += records.Len()
				for recordIndex := 0; recordIndex < records.Len(); recordIndex++ {
					record := records.At(recordIndex)
					if record.Attributes().AsRaw()["canopen.raw.transaction"] == "device.firmware" {
						transactionRecordFound = true
					}
				}
			}
		}
	}
	assert.Equal(t, 1, recordCount)
	assert.True(t, transactionRecordFound)
}

func TestReceiver_RawTransactionOnce(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 10 * time.Millisecond
	cfg.Raw.Transactions = []RawTransactionConfig{{
		Name: "device.once", CobID: 0x501, Payload: []byte{0x08, 0x80}, Mode: "once", Timeout: time.Second,
		Response: RawResponseConfig{
			CobID:  0x481,
			Match:  []RawMatchByte{{ByteOffset: 0, Value: 0x08}},
			Fields: []FieldConfig{{Name: "device.value", Type: codec.Uint8}},
		},
	}}
	require.NoError(t, cfg.Validate())

	r := newCanopenReceiver(cfg, receivertest.NewNopSettings(metadata.Type), fakeBusDialer{bus: bus})
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, r.Shutdown(context.Background())) }()

	recvCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request, err := monitor.Recv(recvCtx)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x501), request.ID)
	assert.Equal(t, []byte{0x08, 0x80}, request.Data)

	response := cantransport.Frame{ID: 0x481, Data: []byte{0x08, 0x55}}
	bus.Inject(response)
	waitForFrameData(t, recvCtx, monitor, response.Data)
	noRepeatCtx, stopWaiting := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stopWaiting()
	_, err = monitor.Recv(noRepeatCtx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestReceiver_RawTransactionPollRetriesAfterTimeout(t *testing.T) {
	bus := cantransport.NewFakeBus()
	monitor, err := bus.Dial(context.Background(), "vcan0")
	require.NoError(t, err)
	defer monitor.Close()

	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "vcan0"
	cfg.ReadTimeout = 10 * time.Millisecond
	cfg.Metrics.Enabled = false
	cfg.Raw.Transactions = []RawTransactionConfig{{
		Name:       "device.firmware",
		CobID:      0x51E,
		Payload:    []byte{0x08, 0x80},
		Timeout:    30 * time.Millisecond,
		Interval:   time.Hour,
		Retry:      true,
		Backoff:    time.Millisecond,
		MaxBackoff: time.Millisecond,
		MaxRetries: intPointer(1),
		Response: RawResponseConfig{
			CobID:  0x49E,
			Match:  []RawMatchByte{{ByteOffset: 0, Value: 0x08}},
			Fields: []FieldConfig{{Name: "device.version", BitOffset: 8, Type: codec.Uint32}},
		},
	}}
	require.NoError(t, cfg.Validate())

	settings := receivertest.NewNopSettings(metadata.Type)
	logCore, observedLogs := observer.New(zap.DebugLevel)
	settings.Logger = zap.New(logCore)
	r := newCanopenReceiver(cfg, settings, fakeBusDialer{bus: bus})
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	defer func() { require.NoError(t, r.Shutdown(context.Background())) }()

	recvCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	firstRequest, err := monitor.Recv(recvCtx)
	require.NoError(t, err)
	secondRequest, err := monitor.Recv(recvCtx)
	require.NoError(t, err)
	assert.Equal(t, firstRequest.ID, secondRequest.ID)
	assert.Equal(t, firstRequest.Data, secondRequest.Data)
	noMoreRequestsCtx, stopWaiting := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stopWaiting()
	_, err = monitor.Recv(noMoreRequestsCtx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	entries := observedLogs.All()
	require.Len(t, entries, 2)
	assert.Equal(t, "canopen: raw transaction attempt failed; retry scheduled", entries[0].Message)
	assert.Equal(t, "device.firmware", entries[0].ContextMap()["transaction"])
	assert.Equal(t, "canopen: raw transaction failed; retry limit reached", entries[1].Message)
	assert.Equal(t, int64(2), entries[1].ContextMap()["attempts"])

}
