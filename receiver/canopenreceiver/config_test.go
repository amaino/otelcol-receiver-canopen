package canopenreceiver

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap/confmaptest"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
)

func TestLoadConfig(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	cfg := createDefaultConfig().(*Config)
	require.NoError(t, cm.Unmarshal(cfg))

	assert.Equal(t, "can0", cfg.Interface)
	assert.Equal(t, time.Second, cfg.ReadTimeout)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, 10*time.Second, cfg.Metrics.FlushInterval)
	assert.True(t, cfg.Logs.Enabled)

	require.True(t, cfg.Sniff.Enabled)
	assert.True(t, cfg.Sniff.Heartbeat.Logs)
	assert.True(t, cfg.Sniff.EMCY.Metrics)
	assert.True(t, cfg.Sniff.EMCY.Logs)
	assert.True(t, cfg.Sniff.SDO.Raw.Metrics)
	assert.True(t, cfg.Sniff.SDO.Raw.Logs)
	require.Len(t, cfg.Sniff.SDO.Channels, 2)
	assert.EqualValues(t, 0x611, cfg.Sniff.SDO.Channels[1].ClientToServerCobID)
	require.Len(t, cfg.Sniff.SDO.Objects, 1)
	assert.EqualValues(t, 30, cfg.Sniff.SDO.Objects[0].NodeID)
	assert.EqualValues(t, 0x20F0, cfg.Sniff.SDO.Objects[0].Index)
	assert.EqualValues(t, 0x11, cfg.Sniff.SDO.Objects[0].SubIndex)
	assert.Equal(t, codec.Uint32, cfg.Sniff.SDO.Objects[0].Type)
	require.Len(t, cfg.Sniff.SDO.Raw.Filters, 1)
	require.NotNil(t, cfg.Sniff.SDO.Raw.Filters[0].NodeID)
	assert.EqualValues(t, 1, *cfg.Sniff.SDO.Raw.Filters[0].NodeID)
	require.NotNil(t, cfg.Sniff.SDO.Raw.Filters[0].Index)
	assert.EqualValues(t, 0x2001, *cfg.Sniff.SDO.Raw.Filters[0].Index)
	require.NotNil(t, cfg.Sniff.SDO.Raw.Filters[0].SubIndex)
	assert.EqualValues(t, 0, *cfg.Sniff.SDO.Raw.Filters[0].SubIndex)
	require.Len(t, cfg.Sniff.PDOs, 1)
	pdo := cfg.Sniff.PDOs[0]
	assert.Equal(t, "motor_tpdo1", pdo.Name)
	assert.EqualValues(t, 0x181, pdo.CobID)
	require.Len(t, pdo.Signals, 1)
	sig := pdo.Signals[0]
	assert.Equal(t, "canopen.motor.speed", sig.Name)
	assert.Equal(t, codec.Int16, sig.Type)
	assert.Equal(t, 0.1, sig.Scale)
	assert.Equal(t, "rpm", sig.Unit)
	assert.True(t, sig.Metrics)
	assert.Equal(t, "x", sig.Attributes["axis"])
	assert.Equal(t, 200, sig.Attributes["priority"])

	require.NoError(t, cfg.Validate())
}

func validBaseConfig() *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "can0"
	cfg.Sniff.Enabled = true
	cfg.Sniff.PDOs = []PDOConfig{
		{
			Name:  "pdo1",
			CobID: 0x181,
			Signals: []SignalConfig{
				{Name: "sig1", Type: codec.Uint8, Metrics: true},
			},
		},
	}
	return cfg
}

func TestConfig_Validate_OK(t *testing.T) {
	cfg := validBaseConfig()
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_EmptyInterface(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Interface = ""
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SniffNotEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.Enabled = false
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_NoSignalEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Metrics.Enabled = false
	cfg.Logs.Enabled = false
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_BadCobID(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.PDOs[0].CobID = 0
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_DuplicatePDOName(t *testing.T) {
	cfg := validBaseConfig()
	dup := cfg.Sniff.PDOs[0]
	dup.CobID = 0x182
	cfg.Sniff.PDOs = append(cfg.Sniff.PDOs, dup)
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_DuplicateCobID(t *testing.T) {
	cfg := validBaseConfig()
	dup := cfg.Sniff.PDOs[0]
	dup.Name = "pdo2"
	cfg.Sniff.PDOs = append(cfg.Sniff.PDOs, dup)
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_EmitRequiresSignalEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Logs.Enabled = false
	cfg.Sniff.PDOs[0].Signals[0].Logs = true
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOEmitRequiresLogsEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Logs.Enabled = false
	cfg.Sniff.SDO.Raw.Logs = true
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_OutputSelectorsRequireConfiguredSignal(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.PDOs[0].Signals[0].Metrics = false
	cfg.Sniff.PDOs[0].Signals[0].Logs = false
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SDOFilterNodeID(t *testing.T) {
	cfg := validBaseConfig()
	nodeID := uint8(128)
	cfg.Sniff.SDO.Raw.Filters = []SDOFilter{{NodeID: &nodeID}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOChannels(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.SDO.Channels = []SDOChannelConfig{
		{NodeID: 1, ClientToServerCobID: 0x601, ServerToClientCobID: 0x581},
		{NodeID: 1, ClientToServerCobID: 0x611, ServerToClientCobID: 0x591},
	}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SDOChannelAllowsNonstandardCOBIDs(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.SDO.Channels = []SDOChannelConfig{{
		NodeID: 1, ClientToServerCobID: 0x501, ServerToClientCobID: 0x581,
	}}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SDOChannelRejectsExtendedCOBIDs(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.SDO.Channels = []SDOChannelConfig{{
		NodeID: 1, ClientToServerCobID: 0x800, ServerToClientCobID: 0x581,
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOObjectRequiresMetricsEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Metrics.Enabled = false
	cfg.Sniff.SDO.Objects = []SDOObjectConfig{{
		NodeID: 1, Index: 0x20F0, SubIndex: 0x11,
		SignalConfig: SignalConfig{Name: "firmware", Type: codec.Uint32, Metrics: true},
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawEmitRequiresLogsEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Logs.Enabled = false
	cfg.Sniff.Raw.Logs = true
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawCobIDOutOfRange(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.Raw.CobIDs = []uint32{0x800}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawCobIDDuplicate(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.Raw.CobIDs = []uint32{0x50E, 0x50E}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawCobIDOK(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sniff.Raw.Metrics = true
	cfg.Sniff.Raw.Logs = true
	cfg.Sniff.Raw.CobIDs = []uint32{0x50E, 0x48E}
	require.NoError(t, cfg.Validate())
}
