package sniffer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/emit"
)

func TestSniffer_PDO(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		PDOs: map[uint32]PDODef{
			0x181: {
				Name:  "motor_tpdo1",
				CobID: 0x181,
				Signals: []PDOSignal{
					{Name: "canopen.motor.speed", BitOffset: 0, Type: codec.Int16, Scale: 0.1, EmitMetric: true},
				},
			},
		},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// int16 le 1000 = 0x03E8 -> bytes E8 03
	s.HandleFrame(cantransport.Frame{ID: 0x181, Data: []byte{0xE8, 0x03}}, metrics, logs)

	require.False(t, metrics.Empty())
	md := metrics.Emit()
	require.Equal(t, 1, md.ResourceMetrics().Len())
	m := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "canopen.motor.speed", m.Name())
	dp := m.Gauge().DataPoints().At(0)
	assert.InDelta(t, 100.0, dp.DoubleValue(), 0.001)
}

func TestSniffer_Heartbeat_StateChangeLogging(t *testing.T) {
	s := New(Config{InterfaceName: "can0", HeartbeatEmitLog: true, HeartbeatEmitMetric: true})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// node 1 -> operational (0x05)
	s.HandleFrame(cantransport.Frame{ID: 0x701, Data: []byte{0x05}}, metrics, logs)
	require.False(t, logs.Empty())
	ld := logs.Emit()
	assert.Equal(t, 1, ld.ResourceLogs().Len())

	metrics.Emit() // reset

	// repeat same state: metric updates again, but no new log (state unchanged)
	s.HandleFrame(cantransport.Frame{ID: 0x701, Data: []byte{0x05}}, metrics, logs)
	assert.True(t, logs.Empty())
	assert.False(t, metrics.Empty())
}

func TestSniffer_EMCY(t *testing.T) {
	s := New(Config{InterfaceName: "can0", EMCYEmitLog: true, EMCYEmitMetric: true})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// node 2, error code 0x2310 (current), register 0x01
	s.HandleFrame(cantransport.Frame{ID: 0x082, Data: []byte{0x10, 0x23, 0x01, 0, 0, 0, 0, 0}}, metrics, logs)

	require.False(t, logs.Empty())
	require.False(t, metrics.Empty())
	ld := logs.Emit()
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Contains(t, lr.Body().Str(), "0x2310")
}

func TestSniffer_SDORequestAndAbort(t *testing.T) {
	s := New(Config{InterfaceName: "can0", SDOEmitLog: true, SDOEmitMetric: true})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// Client 0x601 asks node 1 to upload object 0x2001:00.
	s.HandleFrame(
		cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0}},
		metrics,
		logs,
	)
	// Node 1 rejects the request with abort code 0x06020000.
	s.HandleFrame(
		cantransport.Frame{ID: 0x581, Data: []byte{0x80, 0x01, 0x20, 0x00, 0, 0, 0x02, 0x06}},
		metrics,
		logs,
	)

	require.False(t, metrics.Empty())
	require.False(t, logs.Empty())
	md := metrics.Emit()
	metric := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "canopen.sdo.transfers", metric.Name())
	assert.Equal(t, 1, metric.Sum().DataPoints().Len())

	ld := logs.Emit()
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, records.Len())
	assert.Contains(t, records.At(0).Body().Str(), "server_to_client")
	assert.Equal(t, "abort", records.At(0).Attributes().AsRaw()["canopen.sdo.operation"])
	assert.Equal(t, int64(0x2001), records.At(0).Attributes().AsRaw()["canopen.sdo.index"])
	assert.Equal(t, "0x06020000", records.At(0).Attributes().AsRaw()["canopen.sdo.abort_code"])
}

func TestSniffer_SDOReassemblesSegmentedUpload(t *testing.T) {
	s := New(Config{InterfaceName: "can0", SDOEmitLog: true})
	logs := emit.NewLogsBuilder()

	// Upload object 0x2001:00 in two segments: "hello w" + "orld".
	s.HandleFrame(
		cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00}},
		nil,
		logs,
	)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x41, 0x01, 0x20, 0x00, 11, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x60}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x00, 'h', 'e', 'l', 'l', 'o', ' ', 'w'}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x70}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x17, 'o', 'r', 'l', 'd', 0, 0, 0}}, nil, logs)

	require.False(t, logs.Empty())
	attrs := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().AsRaw()
	assert.Equal(t, int64(0x2001), attrs["canopen.sdo.index"])
	assert.Equal(t, "68656C6C6F20776F726C64", attrs["canopen.sdo.data"])
}

func TestSniffer_SDOFilters(t *testing.T) {
	nodeID := uint8(1)
	index := uint16(0x2001)
	subIndex := uint8(0)
	s := New(Config{
		InterfaceName: "can0",
		SDOEmitLog:    true,
		SDOFilters: []SDOFilter{
			{NodeID: &nodeID, Index: &index, SubIndex: &subIndex},
		},
	})
	logs := emit.NewLogsBuilder()

	s.HandleFrame(
		cantransport.Frame{ID: 0x601, Data: []byte{0x2F, 0x01, 0x20, 0x00, 1, 0, 0, 0}},
		nil,
		logs,
	)
	s.HandleFrame(
		cantransport.Frame{ID: 0x601, Data: []byte{0x2F, 0x02, 0x20, 0x00, 1, 0, 0, 0}},
		nil,
		logs,
	)
	s.HandleFrame(
		cantransport.Frame{ID: 0x602, Data: []byte{0x2F, 0x01, 0x20, 0x00, 1, 0, 0, 0}},
		nil,
		logs,
	)

	require.False(t, logs.Empty())
	records := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 1, records.Len())
	assert.Equal(t, int64(0x2001), records.At(0).Attributes().AsRaw()["canopen.sdo.index"])
}

func TestSniffer_SDONodeFilterIncludesSegmentedTransfers(t *testing.T) {
	nodeID := uint8(1)
	s := New(Config{
		InterfaceName: "can0",
		SDOEmitLog:    true,
		SDOFilters:    []SDOFilter{{NodeID: &nodeID}},
	})
	logs := emit.NewLogsBuilder()

	s.HandleFrame(
		cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00}},
		nil,
		logs,
	)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x41, 0x01, 0x20, 0x00, 1, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x60}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x0F, 'x', 0, 0, 0, 0, 0, 0}}, nil, logs)

	require.False(t, logs.Empty())
}

func TestSniffer_UnknownCobID_Ignored(t *testing.T) {
	s := New(Config{InterfaceName: "can0"})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()
	s.HandleFrame(cantransport.Frame{ID: 0x999, Data: []byte{1, 2, 3}}, metrics, logs)
	assert.True(t, metrics.Empty())
	assert.True(t, logs.Empty())
}
