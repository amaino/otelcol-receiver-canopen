// Package canopenreceiver implements an OpenTelemetry Collector receiver for
// CANopen traffic over Linux SocketCAN. This version supports passive
// sniffing of standard SDO (including segmented transfers), PDO/EMCY/heartbeat
// traffic, and declarative raw frames. Configuration controls which fields
// are decoded and whether each is emitted as a metric, a log, or both.
// Active SDO polling is added in a later commit.
package canopenreceiver

import (
	"errors"
	"fmt"
	"math"
	"time"

	"go.opentelemetry.io/collector/component"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
)

// MetricType selects the OTel metric data point type for a signal emitted as
// a metric.
type MetricType string

const (
	MetricGauge MetricType = "gauge"
	MetricSum   MetricType = "sum"
)

func (t MetricType) validate() error {
	switch t {
	case "", MetricGauge, MetricSum:
		return nil
	default:
		return fmt.Errorf("invalid metric_type %q: must be one of gauge, sum", t)
	}
}

// FieldConfig describes how to decode and emit a single named value
// extracted from a CAN frame or completed SDO payload. Declaring several
// FieldConfig entries against one payload (a PDO, a raw message, a
// completed SDO transfer, or a raw transaction's response) decodes a
// struct - e.g. a multi-field CANopen record - one FieldConfig per member.
type FieldConfig struct {
	// Name is the metric name (metric emission), and the key this field's
	// value is stored under in the structured log body map (log
	// emission). Must be unique within its containing scope (e.g. one
	// PDO's field list).
	Name string `mapstructure:"name"`

	// BitOffset is the 0-based, LSB-first bit offset into the frame payload
	// where this field starts.
	BitOffset int `mapstructure:"bit_offset"`

	// Type is the CANopen data type used to interpret the bits/bytes at
	// BitOffset. One of the codec.DataType constants.
	Type codec.DataType `mapstructure:"type"`

	// ByteLen is the number of bytes to read for Type == bytes or
	// visible_string. Ignored for fixed-width numeric types.
	ByteLen int `mapstructure:"byte_len"`

	// Scale and Offset apply a linear transform (value*Scale + Offset) to
	// numeric fields before emission. Scale defaults to 1 when zero.
	Scale  float64 `mapstructure:"scale"`
	Offset float64 `mapstructure:"offset"`

	// Unit is an optional UCUM-ish unit string attached to metrics/logs.
	Unit string `mapstructure:"unit"`

	Metrics bool `mapstructure:"metrics"`
	Logs    bool `mapstructure:"logs"`

	// MetricType selects gauge vs. sum when Metrics is enabled. Defaults
	// to gauge.
	MetricType MetricType `mapstructure:"metric_type"`

	// Attributes are additional static resource/datapoint attributes
	// attached to every emitted metric data point / log record for this
	// field. Values may be strings, bools, or numbers; numeric YAML
	// scalars are preserved as numeric OTLP attributes (see
	// validateStaticAttributes and emit.putAttribute).
	Attributes map[string]any `mapstructure:"attributes"`
}

func (s *FieldConfig) validate(scope string) error {
	if s.Name == "" {
		return fmt.Errorf("%s: name must not be empty", scope)
	}
	if s.BitOffset < 0 {
		return fmt.Errorf("%s %q: bit_offset must be >= 0", scope, s.Name)
	}
	if !s.Type.Valid() {
		return fmt.Errorf("%s %q: unsupported type %q", scope, s.Name, s.Type)
	}
	if s.Type == codec.Bytes || s.Type == codec.VisibleString {
		if s.ByteLen <= 0 {
			return fmt.Errorf("%s %q: byte_len must be > 0 for type %q", scope, s.Name, s.Type)
		}
		if s.BitOffset%8 != 0 {
			return fmt.Errorf("%s %q: bit_offset must be byte-aligned for type %q", scope, s.Name, s.Type)
		}
		if s.Metrics {
			return fmt.Errorf("%s %q: metrics is not supported for type %q; use logs instead", scope, s.Name, s.Type)
		}
	}
	if err := s.MetricType.validate(); err != nil {
		return fmt.Errorf("%s %q: %w", scope, s.Name, err)
	}
	if err := validateStaticAttributes(scope+" "+s.Name, s.Attributes); err != nil {
		return err
	}
	return nil
}

// validateStaticAttributes checks that each configured attribute value has a
// type the confmap YAML decoder can actually produce: string, bool, int
// (the platform word size; only used for values that fit in it), int64
// (larger signed values, notably on 32-bit builds), uint64 (positive values
// too large for int64), or float64 (values with a decimal point, or ones
// too large for int64/uint64). No other types are reachable from config, so
// none of Go's narrower numeric types (int8/16/32, uint/8/16/32, float32)
// are accepted here.
func validateStaticAttributes(scope string, attrs map[string]any) error {
	for key, value := range attrs {
		switch value := value.(type) {
		case string, bool, int, int64, float64:
		case uint64:
			if value > math.MaxInt64 {
				return fmt.Errorf("%s attribute %q: uint64 value %d exceeds supported int64 range", scope, key, value)
			}
		default:
			return fmt.Errorf("%s attribute %q: unsupported static attribute type %T", scope, key, value)
		}
	}
	return nil
}

// PDOConfig describes a single PDO (or any other frame identified by a fixed
// COB-ID) to decode.
type PDOConfig struct {
	// Name identifies this PDO definition in logs/errors.
	Name string `mapstructure:"name"`
	// CobID is the CAN arbitration ID (COB-ID) this PDO is transmitted on.
	CobID uint32 `mapstructure:"cob_id"`
	// Fields are the values to decode from this PDO's payload. Multiple
	// entries decode a struct from one frame.
	Fields []FieldConfig `mapstructure:"fields"`
}

func (p *PDOConfig) validate() error {
	if p.Name == "" {
		return errors.New("pdo: name must not be empty")
	}
	if p.CobID == 0 || p.CobID > 0x1FFFFFFF {
		return fmt.Errorf("pdo %q: cob_id 0x%X out of range", p.Name, p.CobID)
	}
	if len(p.Fields) == 0 {
		return fmt.Errorf("pdo %q: must declare at least one field", p.Name)
	}
	seen := make(map[string]struct{}, len(p.Fields))
	for i := range p.Fields {
		if err := p.Fields[i].validate(fmt.Sprintf("pdo %q field", p.Name)); err != nil {
			return err
		}
		if _, dup := seen[p.Fields[i].Name]; dup {
			return fmt.Errorf("pdo %q: duplicate field name %q", p.Name, p.Fields[i].Name)
		}
		seen[p.Fields[i].Name] = struct{}{}
	}
	return nil
}

// SimpleEventConfig configures emission for a built-in sniffed event class
// (heartbeat/NMT state changes and EMCY emergency messages) that doesn't need
// a user-declared signal table.
type SimpleEventConfig struct {
	Metrics bool `mapstructure:"metrics"`
	Logs    bool `mapstructure:"logs"`
}

func (s *SimpleEventConfig) validate(name string) error {
	return nil
}

// SDOObjectConfig identifies one SDO object (node/index/sub-index) and
// decodes one or more named values from its completed transfer payload.
// Multiple Fields entries decode a struct - e.g. a multi-field CANopen
// record - from one object; a single entry decodes a plain scalar object.
type SDOObjectConfig struct {
	NodeID   uint8         `mapstructure:"node_id"`
	Index    uint16        `mapstructure:"index"`
	SubIndex uint8         `mapstructure:"sub_index"`
	Fields   []FieldConfig `mapstructure:"fields"`
}

func (s *SDOObjectConfig) validate(scope string) error {
	if s.NodeID < 1 || s.NodeID > 127 {
		return fmt.Errorf("%s: node_id %d out of range 1..127", scope, s.NodeID)
	}
	if len(s.Fields) == 0 {
		return fmt.Errorf("%s: must declare at least one field", scope)
	}
	seen := make(map[string]struct{}, len(s.Fields))
	for i := range s.Fields {
		if err := s.Fields[i].validate(scope + " field"); err != nil {
			return err
		}
		if _, dup := seen[s.Fields[i].Name]; dup {
			return fmt.Errorf("%s: duplicate field name %q", scope, s.Fields[i].Name)
		}
		seen[s.Fields[i].Name] = struct{}{}
	}
	return nil
}

// SDOSniffConfig configures passive observation of SDO frames exchanged by
// other nodes. It never initiates an SDO transfer.
type SDOSniffConfig struct {
	Channels []SDOChannelConfig `mapstructure:"channels"`
	Objects  []SDOObjectConfig  `mapstructure:"objects"`
}

// SDOChannelConfig identifies one standard CANopen SDO client/server COB-ID
// pair. Multiple channels may use the same node ID.
type SDOChannelConfig struct {
	NodeID              uint8  `mapstructure:"node_id"`
	ClientToServerCobID uint32 `mapstructure:"client_to_server_cob_id"`
	ServerToClientCobID uint32 `mapstructure:"server_to_client_cob_id"`
}

func (c *SDOChannelConfig) validate(index int) error {
	if c.NodeID == 0 || c.NodeID > 127 {
		return fmt.Errorf("sdo.sniff.channels[%d]: node_id must be in range 1..127", index)
	}
	if c.ClientToServerCobID > 0x7FF {
		return fmt.Errorf("sdo.sniff.channels[%d]: client_to_server_cob_id must be a standard CAN ID in range 0x000..0x7FF", index)
	}
	if c.ServerToClientCobID > 0x7FF {
		return fmt.Errorf("sdo.sniff.channels[%d]: server_to_client_cob_id must be a standard CAN ID in range 0x000..0x7FF", index)
	}
	return nil
}

func (s *SDOSniffConfig) validate() error {
	seen := make(map[uint32]struct{}, len(s.Channels)*2)
	for i := range s.Channels {
		if err := s.Channels[i].validate(i); err != nil {
			return err
		}
		for _, cobID := range []uint32{s.Channels[i].ClientToServerCobID, s.Channels[i].ServerToClientCobID} {
			if _, duplicate := seen[cobID]; duplicate {
				return fmt.Errorf("sdo.sniff.channels: duplicate cob_id 0x%03X", cobID)
			}
			seen[cobID] = struct{}{}
		}
	}
	objectSeen := make(map[string]struct{}, len(s.Objects))
	for i := range s.Objects {
		if err := s.Objects[i].validate(fmt.Sprintf("sdo.sniff.objects[%d]", i)); err != nil {
			return err
		}
		key := fmt.Sprintf("%d:%04X:%02X", s.Objects[i].NodeID, s.Objects[i].Index, s.Objects[i].SubIndex)
		if _, duplicate := objectSeen[key]; duplicate {
			return fmt.Errorf("sdo.sniff.objects: duplicate object %s", key)
		}
		objectSeen[key] = struct{}{}
	}
	return nil
}

// SDOPollConfig declares standard CANopen SDO objects to actively poll.
// Config/validation only: nothing in this receiver initiates an SDO
// transfer yet (see this package's doc comment). Declaring entries here
// has no runtime effect today.
type SDOPollConfig struct {
	Interval time.Duration     `mapstructure:"interval"`
	Objects  []SDOObjectConfig `mapstructure:"objects"`
}

func (p *SDOPollConfig) validate() error {
	if len(p.Objects) == 0 {
		return nil
	}
	if p.Interval <= 0 {
		return errors.New("sdo.poll: interval must be > 0 when objects are declared")
	}
	seen := make(map[string]struct{}, len(p.Objects))
	for i := range p.Objects {
		if err := p.Objects[i].validate("sdo.poll.objects"); err != nil {
			return fmt.Errorf("sdo.poll.objects[%d]: %w", i, err)
		}
		key := fmt.Sprintf("%d:%04X:%02X", p.Objects[i].NodeID, p.Objects[i].Index, p.Objects[i].SubIndex)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("sdo.poll.objects: duplicate object %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// SDOConfig groups standard-CANopen-SDO config: passive Sniff (real,
// working today) and active Poll (config/validation-only for now; see
// SDOPollConfig).
type SDOConfig struct {
	Sniff SDOSniffConfig `mapstructure:"sniff"`
	Poll  SDOPollConfig  `mapstructure:"poll"`
}

func (s *SDOConfig) validate() error {
	if err := s.Sniff.validate(); err != nil {
		return err
	}
	return s.Poll.validate()
}

// RawMatchByte is a byte-equality condition used to discriminate between
// multiple raw message shapes that share the same COB-ID (e.g. several
// vendor commands multiplexed onto one CAN ID, distinguished by an echoed
// command word at a fixed offset).
type RawMatchByte struct {
	ByteOffset int   `mapstructure:"byte_offset"`
	Value      uint8 `mapstructure:"value"`
}

func (m *RawMatchByte) validate(scope string) error {
	if m.ByteOffset < 0 || m.ByteOffset > 7 {
		return fmt.Errorf("%s: byte_offset must be 0..7", scope)
	}
	return nil
}

// RawMessageConfig declares a decodable shape for frames on a given COB-ID
// that are not standard CANopen SDO/PDO framing (e.g. a vendor
// application-layer command/response). Match narrows which frames on
// CobID this definition applies to (useful when one COB-ID multiplexes
// several command types); an empty Match matches every frame on CobID.
// Fields decode values from the payload exactly like a PDO's fields,
// using the same types/bit offsets/scale, so no bespoke processor is
// needed for fixed-layout vendor protocols; multiple entries decode a
// struct from one frame.
type RawMessageConfig struct {
	Name   string         `mapstructure:"name"`
	CobID  uint32         `mapstructure:"cob_id"`
	Match  []RawMatchByte `mapstructure:"match"`
	Fields []FieldConfig  `mapstructure:"fields"`
}

func (r *RawMessageConfig) validate() error {
	if r.Name == "" {
		return errors.New("raw.sniff.messages: name must not be empty")
	}
	if r.CobID == 0 || r.CobID > 0x7FF {
		return fmt.Errorf("raw message %q: cob_id 0x%X out of range for an 11-bit standard COB-ID", r.Name, r.CobID)
	}
	for i := range r.Match {
		if err := r.Match[i].validate(fmt.Sprintf("raw message %q match[%d]", r.Name, i)); err != nil {
			return err
		}
	}
	if len(r.Fields) == 0 {
		return fmt.Errorf("raw message %q: must declare at least one field", r.Name)
	}
	seen := make(map[string]struct{}, len(r.Fields))
	for i := range r.Fields {
		if err := r.Fields[i].validate(fmt.Sprintf("raw message %q field", r.Name)); err != nil {
			return err
		}
		if _, dup := seen[r.Fields[i].Name]; dup {
			return fmt.Errorf("raw message %q: duplicate field name %q", r.Name, r.Fields[i].Name)
		}
		seen[r.Fields[i].Name] = struct{}{}
	}
	return nil
}

// RawFrameConfig configures passive capture of arbitrary CAN frames that are
// not decoded by any other sniffing feature. By default (no Messages
// declared for a CobID) it performs no protocol interpretation and matching
// frames are emitted as their raw hex payload; when a Messages entry
// declares field layout for a CobID, matching frames are decoded into named
// signals instead. This is intended for vendor/proprietary traffic riding on
// the bus (e.g. diagnostic or service-tool protocols) without teaching this
// receiver protocol-specific semantics beyond a declarative field layout.
type RawFrameConfig struct {
	Metrics bool `mapstructure:"metrics"`
	Logs    bool `mapstructure:"logs"`
	// CobIDs lists the exact 11-bit standard COB-IDs to capture as raw
	// frames. Frames on IDs already handled by another sniffing feature
	// (a configured PDO, heartbeat, EMCY, or standard SDO) are not
	// affected by this list unless explicitly included here, in which
	// case the raw capture takes precedence for that COB-ID.
	CobIDs []uint32 `mapstructure:"cob_ids"`
	// Messages declare a decodable field layout for frames on a CobID,
	// optionally narrowed by Match. When a frame's CobID has one or more
	// Messages and matches one of them, its signals are decoded and
	// emitted under their configured names instead of a raw hex dump.
	Messages []RawMessageConfig `mapstructure:"messages"`
}

func (r *RawFrameConfig) validate() error {
	seen := make(map[uint32]struct{}, len(r.CobIDs))
	for _, id := range r.CobIDs {
		if id > 0x7FF {
			return fmt.Errorf("raw.sniff.cob_ids: 0x%X out of range for an 11-bit standard COB-ID", id)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("raw.sniff.cob_ids: duplicate cob_id 0x%X", id)
		}
		seen[id] = struct{}{}
	}
	seenNames := make(map[string]struct{}, len(r.Messages))
	for i := range r.Messages {
		if err := r.Messages[i].validate(); err != nil {
			return fmt.Errorf("raw.sniff.messages[%d]: %w", i, err)
		}
		if _, dup := seenNames[r.Messages[i].Name]; dup {
			return fmt.Errorf("raw.sniff.messages: duplicate name %q", r.Messages[i].Name)
		}
		seenNames[r.Messages[i].Name] = struct{}{}
	}
	return nil
}

// RawResponseConfig declares how a RawTransactionConfig's correlated reply
// would be decoded, once the receiver supports correlating it. Config/
// validation only for now - see RawTransactionConfig.
type RawResponseConfig struct {
	CobID  uint32        `mapstructure:"cob_id"`
	Fields []FieldConfig `mapstructure:"fields"`
}

func (r *RawResponseConfig) validate(scope string) error {
	if r.CobID == 0 || r.CobID > 0x7FF {
		return fmt.Errorf("%s.response: cob_id 0x%X out of range for an 11-bit standard COB-ID", scope, r.CobID)
	}
	if len(r.Fields) == 0 {
		return fmt.Errorf("%s.response: must declare at least one field", scope)
	}
	seen := make(map[string]struct{}, len(r.Fields))
	for i := range r.Fields {
		if err := r.Fields[i].validate(scope + ".response field"); err != nil {
			return err
		}
		if _, dup := seen[r.Fields[i].Name]; dup {
			return fmt.Errorf("%s.response: duplicate field name %q", scope, r.Fields[i].Name)
		}
		seen[r.Fields[i].Name] = struct{}{}
	}
	return nil
}

// RawTransactionConfig declares a raw CAN request/response poll cycle: send
// the request, wait for the correlated reply (or Timeout), then wait Interval before polling again -
// not a fixed-rate blind retransmit. Config/validation only for now:
// nothing in this receiver transmits a request or correlates a reply to it
// yet - a planned future addition, same status as SDOPollConfig. Declaring
// one here is inert today.
type RawTransactionConfig struct {
	Name  string `mapstructure:"name"`
	CobID uint32 `mapstructure:"cob_id"`
	// Payload is the fixed request frame's payload bytes (1-8).
	Payload []uint8 `mapstructure:"payload"`
	// Timeout bounds how long to wait for the correlated response before
	// giving up on that poll cycle.
	Timeout time.Duration `mapstructure:"timeout"`
	// Interval is how long to wait after a response (or Timeout) before
	// sending the next request.
	Interval time.Duration     `mapstructure:"interval"`
	Response RawResponseConfig `mapstructure:"response"`
}

func (r *RawTransactionConfig) validate() error {
	if r.Name == "" {
		return errors.New("raw.transactions: name must not be empty")
	}
	if r.CobID == 0 || r.CobID > 0x7FF {
		return fmt.Errorf("raw transaction %q: cob_id 0x%X out of range for an 11-bit standard COB-ID", r.Name, r.CobID)
	}
	if len(r.Payload) == 0 || len(r.Payload) > 8 {
		return fmt.Errorf("raw transaction %q: payload must be 1..8 bytes", r.Name)
	}
	if r.Timeout <= 0 {
		return fmt.Errorf("raw transaction %q: timeout must be > 0", r.Name)
	}
	if r.Interval <= 0 {
		return fmt.Errorf("raw transaction %q: interval must be > 0", r.Name)
	}
	if err := r.Response.validate(fmt.Sprintf("raw transaction %q", r.Name)); err != nil {
		return err
	}
	return nil
}

// RawConfig groups non-CANopen (vendor/proprietary) CAN traffic config:
// passive Sniff (real, working today) and Transactions (config/validation-
// only for now; see RawTransactionConfig).
type RawConfig struct {
	Sniff        RawFrameConfig         `mapstructure:"sniff"`
	Transactions []RawTransactionConfig `mapstructure:"transactions"`
}

func (r *RawConfig) validate() error {
	if err := r.Sniff.validate(); err != nil {
		return err
	}
	seenNames := make(map[string]struct{}, len(r.Transactions))
	seenCobIDs := make(map[uint32]struct{}, len(r.Transactions))
	for i := range r.Transactions {
		if err := r.Transactions[i].validate(); err != nil {
			return fmt.Errorf("raw.transactions[%d]: %w", i, err)
		}
		if _, dup := seenNames[r.Transactions[i].Name]; dup {
			return fmt.Errorf("raw.transactions: duplicate name %q", r.Transactions[i].Name)
		}
		seenNames[r.Transactions[i].Name] = struct{}{}
		if _, dup := seenCobIDs[r.Transactions[i].CobID]; dup {
			return fmt.Errorf("raw.transactions: duplicate cob_id 0x%X", r.Transactions[i].CobID)
		}
		seenCobIDs[r.Transactions[i].CobID] = struct{}{}
	}
	return nil
}

// validatePDOs checks a list of PDOConfig for internal validity and
// duplicate names/COB-IDs.
func validatePDOs(pdos []PDOConfig) error {
	seen := make(map[string]struct{}, len(pdos))
	cobIDs := make(map[uint32]struct{}, len(pdos))
	for i := range pdos {
		if err := pdos[i].validate(); err != nil {
			return err
		}
		if _, dup := seen[pdos[i].Name]; dup {
			return fmt.Errorf("pdo: duplicate pdo name %q", pdos[i].Name)
		}
		seen[pdos[i].Name] = struct{}{}
		if _, dup := cobIDs[pdos[i].CobID]; dup {
			return fmt.Errorf("pdo: duplicate cob_id 0x%X", pdos[i].CobID)
		}
		cobIDs[pdos[i].CobID] = struct{}{}
	}
	return nil
}

// MetricsConfig configures the metrics signal of this receiver.
type MetricsConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	FlushInterval time.Duration `mapstructure:"flush_interval"`
}

func (m *MetricsConfig) validate() error {
	if !m.Enabled {
		return nil
	}
	if m.FlushInterval <= 0 {
		return errors.New("metrics: flush_interval must be > 0 when metrics is enabled")
	}
	return nil
}

// LogsConfig configures the logs signal of this receiver.
type LogsConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// Config is the configuration for the CANopen receiver. sdo, pdo, and raw
// are independent top-level sections - each is optional on its own, with
// no blanket "sniffing enabled" toggle; an unset section simply emits
// nothing. heartbeat/emcy are always passive (like pdo), so they don't
// have a sniff/poll split; sdo and raw do (see SDOConfig, RawConfig).
type Config struct {
	// Interface is the SocketCAN interface name (e.g. "can0", "vcan0").
	Interface string `mapstructure:"interface"`

	// ReadTimeout bounds how long a single frame receive may block; it also
	// governs how quickly Shutdown can interrupt the read loop. Defaults
	// applied in CreateDefaultConfig.
	ReadTimeout time.Duration `mapstructure:"read_timeout"`

	Metrics MetricsConfig `mapstructure:"metrics"`
	Logs    LogsConfig    `mapstructure:"logs"`

	Heartbeat SimpleEventConfig `mapstructure:"heartbeat"`
	EMCY      SimpleEventConfig `mapstructure:"emcy"`

	SDO SDOConfig   `mapstructure:"sdo"`
	PDO []PDOConfig `mapstructure:"pdo"`
	Raw RawConfig   `mapstructure:"raw"`
}

var _ component.Config = (*Config)(nil)

// Validate checks the configuration for consistency.
func (cfg *Config) Validate() error {
	if cfg.Interface == "" {
		return errors.New("interface must not be empty")
	}
	if cfg.ReadTimeout <= 0 {
		return errors.New("read_timeout must be > 0")
	}
	if !cfg.Metrics.Enabled && !cfg.Logs.Enabled {
		return errors.New("at least one of metrics or logs must be enabled")
	}
	if err := cfg.Metrics.validate(); err != nil {
		return err
	}
	if err := cfg.Heartbeat.validate("heartbeat"); err != nil {
		return err
	}
	if err := cfg.EMCY.validate("emcy"); err != nil {
		return err
	}
	if err := cfg.SDO.validate(); err != nil {
		return err
	}
	if err := cfg.Raw.validate(); err != nil {
		return err
	}
	if err := validatePDOs(cfg.PDO); err != nil {
		return err
	}

	// Cross-check: any signal requesting metrics emission requires
	// metrics.enabled, and any signal requesting logs emission requires
	// logs.enabled, so misconfiguration fails fast instead of silently
	// dropping data. This also covers the still-unimplemented sdo.poll/
	// raw.transactions sections, so their config is already correct the
	// moment the receiver starts acting on it.
	var checkOutputs func(scope string, metrics, logs bool) error
	checkOutputs = func(scope string, metrics, logs bool) error {
		if metrics && !cfg.Metrics.Enabled {
			return fmt.Errorf("%s: metrics output requires metrics.enabled=true", scope)
		}
		if logs && !cfg.Logs.Enabled {
			return fmt.Errorf("%s: logs output requires logs.enabled=true", scope)
		}
		return nil
	}
	if err := checkOutputs("heartbeat", cfg.Heartbeat.Metrics, cfg.Heartbeat.Logs); err != nil {
		return err
	}
	if err := checkOutputs("emcy", cfg.EMCY.Metrics, cfg.EMCY.Logs); err != nil {
		return err
	}
	if err := checkOutputs("raw.sniff", cfg.Raw.Sniff.Metrics, cfg.Raw.Sniff.Logs); err != nil {
		return err
	}
	for _, pdo := range cfg.PDO {
		for _, field := range pdo.Fields {
			if err := checkOutputs(fmt.Sprintf("pdo %q field %q", pdo.Name, field.Name), field.Metrics, field.Logs); err != nil {
				return err
			}
		}
	}
	for _, object := range cfg.SDO.Sniff.Objects {
		for _, field := range object.Fields {
			if err := checkOutputs(fmt.Sprintf("sdo.sniff object %d:%04X:%02X field %q", object.NodeID, object.Index, object.SubIndex, field.Name), field.Metrics, field.Logs); err != nil {
				return err
			}
		}
	}
	for _, object := range cfg.SDO.Poll.Objects {
		for _, field := range object.Fields {
			if err := checkOutputs(fmt.Sprintf("sdo.poll object %d:%04X:%02X field %q", object.NodeID, object.Index, object.SubIndex, field.Name), field.Metrics, field.Logs); err != nil {
				return err
			}
		}
	}
	for _, msg := range cfg.Raw.Sniff.Messages {
		for _, field := range msg.Fields {
			if err := checkOutputs(fmt.Sprintf("raw.sniff message %q field %q", msg.Name, field.Name), field.Metrics, field.Logs); err != nil {
				return err
			}
		}
	}
	for _, txn := range cfg.Raw.Transactions {
		for _, field := range txn.Response.Fields {
			if err := checkOutputs(fmt.Sprintf("raw transaction %q field %q", txn.Name, field.Name), field.Metrics, field.Logs); err != nil {
				return err
			}
		}
	}
	return nil
}

func createDefaultConfig() component.Config {
	return &Config{
		ReadTimeout: 2 * time.Second,
		Metrics: MetricsConfig{
			Enabled:       true,
			FlushInterval: 10 * time.Second,
		},
		Logs: LogsConfig{
			Enabled: true,
		},
	}
}
