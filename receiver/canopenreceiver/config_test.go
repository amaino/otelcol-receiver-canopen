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

	assert.True(t, cfg.Heartbeat.Logs)
	assert.True(t, cfg.EMCY.Metrics)
	assert.True(t, cfg.EMCY.Logs)
	require.Len(t, cfg.SDO.Sniff.Channels, 2)
	assert.EqualValues(t, 0x611, cfg.SDO.Sniff.Channels[1].ClientToServerCobID)
	require.Len(t, cfg.SDO.Sniff.Objects, 1)
	assert.EqualValues(t, 30, cfg.SDO.Sniff.Objects[0].NodeID)
	assert.EqualValues(t, 0x20F0, cfg.SDO.Sniff.Objects[0].Index)
	assert.EqualValues(t, 0x11, cfg.SDO.Sniff.Objects[0].SubIndex)
	require.Len(t, cfg.SDO.Sniff.Objects[0].Fields, 1)
	assert.Equal(t, codec.Uint32, cfg.SDO.Sniff.Objects[0].Fields[0].Type)
	require.Len(t, cfg.PDO, 1)
	pdo := cfg.PDO[0]
	assert.Equal(t, "motor_tpdo1", pdo.Name)
	assert.EqualValues(t, 0x181, pdo.CobID)
	require.Len(t, pdo.Fields, 1)
	field := pdo.Fields[0]
	assert.Equal(t, "canopen.motor.speed", field.Name)
	assert.Equal(t, codec.Int16, field.Type)
	assert.Equal(t, 0.1, field.Scale)
	assert.Equal(t, "rpm", field.Unit)
	assert.True(t, field.Metrics)
	assert.Equal(t, "x", field.Attributes["axis"])
	assert.Equal(t, 200, field.Attributes["priority"])

	require.NoError(t, cfg.Validate())
}

func validBaseConfig() *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.Interface = "can0"
	cfg.PDO = []PDOConfig{
		{
			Name:  "pdo1",
			CobID: 0x181,
			Fields: []FieldConfig{
				{Name: "field1", Type: codec.Uint8, Metrics: true},
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

func TestConfig_Validate_NoSignalEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Metrics.Enabled = false
	cfg.Logs.Enabled = false
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_BadCobID(t *testing.T) {
	cfg := validBaseConfig()
	cfg.PDO[0].CobID = 0
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_DuplicatePDOName(t *testing.T) {
	cfg := validBaseConfig()
	dup := cfg.PDO[0]
	dup.CobID = 0x182
	cfg.PDO = append(cfg.PDO, dup)
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_DuplicateCobID(t *testing.T) {
	cfg := validBaseConfig()
	dup := cfg.PDO[0]
	dup.Name = "pdo2"
	cfg.PDO = append(cfg.PDO, dup)
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_EmitRequiresSignalEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Logs.Enabled = false
	cfg.PDO[0].Fields[0].Logs = true
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_OutputSelectorsRequireConfiguredSignal(t *testing.T) {
	cfg := validBaseConfig()
	cfg.PDO[0].Fields[0].Metrics = false
	cfg.PDO[0].Fields[0].Logs = false
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SDOChannels(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SDO.Sniff.Channels = []SDOChannelConfig{
		{NodeID: 1, ClientToServerCobID: 0x601, ServerToClientCobID: 0x581},
		{NodeID: 1, ClientToServerCobID: 0x611, ServerToClientCobID: 0x591},
	}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SDOChannelAllowsNonstandardCOBIDs(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SDO.Sniff.Channels = []SDOChannelConfig{{
		NodeID: 1, ClientToServerCobID: 0x501, ServerToClientCobID: 0x581,
	}}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SDOChannelRejectsExtendedCOBIDs(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SDO.Sniff.Channels = []SDOChannelConfig{{
		NodeID: 1, ClientToServerCobID: 0x800, ServerToClientCobID: 0x581,
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOObjectRequiresMetricsEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Metrics.Enabled = false
	cfg.SDO.Sniff.Objects = []SDOObjectConfig{{
		NodeID: 1, Index: 0x20F0, SubIndex: 0x11,
		Fields: []FieldConfig{{Name: "firmware", Type: codec.Uint32, Metrics: true}},
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOObjectRequiresAtLeastOneField(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SDO.Sniff.Objects = []SDOObjectConfig{{NodeID: 1, Index: 0x20F0, SubIndex: 0x11}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOObjectStructOK(t *testing.T) {
	// Multiple fields on one object decode a struct from one completed
	// SDO transfer (e.g. an IMPACT_INFO-shaped record).
	cfg := validBaseConfig()
	cfg.SDO.Sniff.Objects = []SDOObjectConfig{{
		NodeID: 1, Index: 0x2160, SubIndex: 0x01,
		Fields: []FieldConfig{
			{Name: "impact.x", BitOffset: 0, Type: codec.Uint8, Logs: true},
			{Name: "impact.y", BitOffset: 8, Type: codec.Uint8, Logs: true},
			{Name: "impact.pin_code", BitOffset: 16, Type: codec.Uint32, Metrics: true},
		},
	}}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_SDOObjectDuplicateFieldName(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SDO.Sniff.Objects = []SDOObjectConfig{{
		NodeID: 1, Index: 0x2160, SubIndex: 0x01,
		Fields: []FieldConfig{
			{Name: "x", Type: codec.Uint8, Logs: true},
			{Name: "x", BitOffset: 8, Type: codec.Uint8, Logs: true},
		},
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_FieldMetricsNotSupportedForVisibleString(t *testing.T) {
	cfg := validBaseConfig()
	cfg.PDO[0].Fields = []FieldConfig{{Name: "f", Type: codec.VisibleString, ByteLen: 4, Metrics: true}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_FieldMetricsNotSupportedForBytes(t *testing.T) {
	cfg := validBaseConfig()
	cfg.PDO[0].Fields = []FieldConfig{{Name: "f", Type: codec.Bytes, ByteLen: 4, Metrics: true}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_FieldLogsOnlyOKForVisibleString(t *testing.T) {
	cfg := validBaseConfig()
	cfg.PDO[0].Fields = []FieldConfig{{Name: "f", Type: codec.VisibleString, ByteLen: 4, Logs: true}}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_RawEmitRequiresLogsEnabled(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Logs.Enabled = false
	cfg.Raw.Sniff.Logs = true
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawCobIDOutOfRange(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.CobIDs = []uint32{0x800}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawCobIDDuplicate(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.CobIDs = []uint32{0x50E, 0x50E}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawCobIDOK(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.Metrics = true
	cfg.Raw.Sniff.Logs = true
	cfg.Raw.Sniff.CobIDs = []uint32{0x50E, 0x48E}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_RawMessageOK(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.Metrics = true
	cfg.Raw.Sniff.Logs = true
	cfg.Raw.Sniff.Messages = []RawMessageConfig{
		{
			Name:  "raw.read_part_no",
			CobID: 0x50E,
			Match: []RawMatchByte{{ByteOffset: 0, Value: 0x08}, {ByteOffset: 1, Value: 0x80}},
			Fields: []FieldConfig{
				{Name: "raw.fw_part_no", BitOffset: 16, Type: codec.Uint32, Metrics: true},
			},
		},
	}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_RawMessageEmptyName(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.Messages = []RawMessageConfig{
		{CobID: 0x50E, Fields: []FieldConfig{{Name: "f", Type: codec.Uint8, Metrics: true}}},
	}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawMessageBadCobID(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.Messages = []RawMessageConfig{
		{Name: "m1", CobID: 0x800, Fields: []FieldConfig{{Name: "f", Type: codec.Uint8, Metrics: true}}},
	}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawMessageNoFields(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.Messages = []RawMessageConfig{{Name: "m1", CobID: 0x50E}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawMessageBadMatchByteOffset(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.Messages = []RawMessageConfig{
		{
			Name:   "m1",
			CobID:  0x50E,
			Match:  []RawMatchByte{{ByteOffset: 8, Value: 0}},
			Fields: []FieldConfig{{Name: "f", Type: codec.Uint8, Metrics: true}},
		},
	}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawMessageDuplicateName(t *testing.T) {
	cfg := validBaseConfig()
	msg := RawMessageConfig{
		Name:   "m1",
		CobID:  0x50E,
		Fields: []FieldConfig{{Name: "f", Type: codec.Uint8, Metrics: true}},
	}
	cfg.Raw.Sniff.Messages = []RawMessageConfig{msg, msg}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawMessageDuplicateFieldName(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Sniff.Messages = []RawMessageConfig{
		{
			Name:  "m1",
			CobID: 0x50E,
			Fields: []FieldConfig{
				{Name: "f", Type: codec.Uint8, Metrics: true},
				{Name: "f", Type: codec.Uint8, Metrics: true},
			},
		},
	}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOPollObjectRequiresInterval(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SDO.Poll.Objects = []SDOObjectConfig{{
		NodeID: 1, Index: 0x20F0, SubIndex: 0x11,
		Fields: []FieldConfig{{Name: "firmware", Type: codec.Uint32, Logs: true}},
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_SDOPollObjectOK(t *testing.T) {
	cfg := validBaseConfig()
	cfg.SDO.Poll.Interval = time.Hour
	cfg.SDO.Poll.Objects = []SDOObjectConfig{{
		NodeID: 1, Index: 0x20F0, SubIndex: 0x11,
		Fields: []FieldConfig{{Name: "firmware", Type: codec.Uint32, Logs: true}},
	}}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_RawTransactionOK(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Transactions = []RawTransactionConfig{{
		Name:     "mcu.firmware_part_no",
		CobID:    0x51E,
		Payload:  []uint8{0x08, 0x80},
		Timeout:  time.Second,
		Interval: time.Hour,
		Response: RawResponseConfig{
			CobID: 0x49E,
			Fields: []FieldConfig{
				{Name: "mcu.firmware_version", BitOffset: 16, Type: codec.Uint32, Logs: true},
			},
		},
	}}
	require.NoError(t, cfg.Validate())
}

func TestConfig_Validate_RawTransactionMissingResponseFields(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Transactions = []RawTransactionConfig{{
		Name:     "mcu.firmware_part_no",
		CobID:    0x51E,
		Payload:  []uint8{0x08, 0x80},
		Timeout:  time.Second,
		Interval: time.Hour,
		Response: RawResponseConfig{CobID: 0x49E},
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawTransactionMissingTimeout(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Raw.Transactions = []RawTransactionConfig{{
		Name:     "mcu.firmware_part_no",
		CobID:    0x51E,
		Payload:  []uint8{0x08, 0x80},
		Interval: time.Hour,
		Response: RawResponseConfig{
			CobID:  0x49E,
			Fields: []FieldConfig{{Name: "mcu.firmware_version", Type: codec.Uint32, Logs: true}},
		},
	}}
	require.Error(t, cfg.Validate())
}

func TestConfig_Validate_RawTransactionDuplicateName(t *testing.T) {
	cfg := validBaseConfig()
	txn := RawTransactionConfig{
		Name:     "mcu.firmware_part_no",
		CobID:    0x51E,
		Payload:  []uint8{0x08, 0x80},
		Timeout:  time.Second,
		Interval: time.Hour,
		Response: RawResponseConfig{
			CobID:  0x49E,
			Fields: []FieldConfig{{Name: "mcu.firmware_version", Type: codec.Uint32, Logs: true}},
		},
	}
	other := txn
	other.CobID = 0x51F
	cfg.Raw.Transactions = []RawTransactionConfig{txn, other}
	require.Error(t, cfg.Validate())
}
