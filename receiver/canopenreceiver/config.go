// Package canopenreceiver implements an OpenTelemetry Collector receiver for
// CANopen traffic over Linux SocketCAN. This version supports passive
// sniffing of PDO/EMCY/heartbeat traffic, fully driven by a declarative
// configuration of which signals to decode and whether each is emitted as a
// metric, a log, or both. Active SDO polling is added in a later commit.
package canopenreceiver

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/component"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
)

// EmitMode controls whether a decoded signal is emitted as a metric, a log,
// or both.
type EmitMode string

const (
	EmitMetrics EmitMode = "metrics"
	EmitLogs    EmitMode = "logs"
	EmitBoth    EmitMode = "both"
)

func (m EmitMode) emitsMetrics() bool { return m == EmitMetrics || m == EmitBoth }
func (m EmitMode) emitsLogs() bool    { return m == EmitLogs || m == EmitBoth }

func (m EmitMode) validate() error {
	switch m {
	case EmitMetrics, EmitLogs, EmitBoth:
		return nil
	default:
		return fmt.Errorf("invalid emit mode %q: must be one of metrics, logs, both", m)
	}
}

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

// SignalConfig describes how to decode and emit a single value extracted
// from a CAN frame (currently: PDO payloads).
type SignalConfig struct {
	// Name is the metric name (metric emission) or log record attribute
	// "canopen.signal.name" value (log emission). Must be unique within its
	// containing scope (a PDO's signal list).
	Name string `mapstructure:"name"`

	// BitOffset is the 0-based, LSB-first bit offset into the frame payload
	// where this signal starts.
	BitOffset int `mapstructure:"bit_offset"`

	// Type is the CANopen data type used to interpret the bits/bytes at
	// BitOffset. One of the codec.DataType constants.
	Type codec.DataType `mapstructure:"type"`

	// ByteLen is the number of bytes to read for Type == bytes or
	// visible_string. Ignored for fixed-width numeric types.
	ByteLen int `mapstructure:"byte_len"`

	// Scale and Offset apply a linear transform (value*Scale + Offset) to
	// numeric signals before emission. Scale defaults to 1 when zero.
	Scale  float64 `mapstructure:"scale"`
	Offset float64 `mapstructure:"offset"`

	// Unit is an optional UCUM-ish unit string attached to metrics/logs.
	Unit string `mapstructure:"unit"`

	// Emit selects whether this signal becomes a metric, a log, or both.
	Emit EmitMode `mapstructure:"emit"`

	// MetricType selects gauge vs. sum when Emit includes metrics. Defaults
	// to gauge.
	MetricType MetricType `mapstructure:"metric_type"`

	// Attributes are additional static resource/datapoint attributes
	// attached to every emitted metric data point / log record for this
	// signal.
	Attributes map[string]string `mapstructure:"attributes"`
}

func (s *SignalConfig) validate(scope string) error {
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
	}
	if err := s.Emit.validate(); err != nil {
		return fmt.Errorf("%s %q: %w", scope, s.Name, err)
	}
	if err := s.MetricType.validate(); err != nil {
		return fmt.Errorf("%s %q: %w", scope, s.Name, err)
	}
	return nil
}

// PDOConfig describes a single PDO (or any other frame identified by a fixed
// COB-ID) to decode when sniffing is enabled.
type PDOConfig struct {
	// Name identifies this PDO definition in logs/errors.
	Name string `mapstructure:"name"`
	// CobID is the CAN arbitration ID (COB-ID) this PDO is transmitted on.
	CobID uint32 `mapstructure:"cob_id"`
	// Signals are the values to decode from this PDO's payload.
	Signals []SignalConfig `mapstructure:"signals"`
}

func (p *PDOConfig) validate() error {
	if p.Name == "" {
		return errors.New("pdo: name must not be empty")
	}
	if p.CobID == 0 || p.CobID > 0x1FFFFFFF {
		return fmt.Errorf("pdo %q: cob_id 0x%X out of range", p.Name, p.CobID)
	}
	if len(p.Signals) == 0 {
		return fmt.Errorf("pdo %q: must declare at least one signal", p.Name)
	}
	seen := make(map[string]struct{}, len(p.Signals))
	for i := range p.Signals {
		if err := p.Signals[i].validate(fmt.Sprintf("pdo %q signal", p.Name)); err != nil {
			return err
		}
		if _, dup := seen[p.Signals[i].Name]; dup {
			return fmt.Errorf("pdo %q: duplicate signal name %q", p.Name, p.Signals[i].Name)
		}
		seen[p.Signals[i].Name] = struct{}{}
	}
	return nil
}

// SimpleEventConfig configures emission for a built-in sniffed event class
// (heartbeat/NMT state changes and EMCY emergency messages) that doesn't need
// a user-declared signal table.
type SimpleEventConfig struct {
	Emit EmitMode `mapstructure:"emit"`
}

func (s *SimpleEventConfig) validate(name string) error {
	if s.Emit == "" {
		return nil
	}
	if err := s.Emit.validate(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// SDOFilter selects passively observed SDO traffic. Unset fields are
// wildcards; at least one configured filter must match for a frame to emit.
type SDOFilter struct {
	NodeID   *uint8  `mapstructure:"node_id"`
	Index    *uint16 `mapstructure:"index"`
	SubIndex *uint8  `mapstructure:"sub_index"`
}

func (f *SDOFilter) validate() error {
	if f.NodeID != nil && (*f.NodeID < 1 || *f.NodeID > 127) {
		return fmt.Errorf("sniff.sdo filter: node_id %d out of range 1..127", *f.NodeID)
	}
	return nil
}

// SDOSniffConfig configures passive observation of SDO frames exchanged by
// other nodes. It never initiates an SDO transfer.
type SDOSniffConfig struct {
	Emit    EmitMode    `mapstructure:"emit"`
	Filters []SDOFilter `mapstructure:"filters"`
}

func (s *SDOSniffConfig) validate() error {
	if s.Emit != "" {
		if err := s.Emit.validate(); err != nil {
			return fmt.Errorf("sniff.sdo: %w", err)
		}
	}
	for i := range s.Filters {
		if err := s.Filters[i].validate(); err != nil {
			return fmt.Errorf("sniff.sdo.filters[%d]: %w", i, err)
		}
	}
	return nil
}

// SniffConfig configures passive traffic sniffing.
type SniffConfig struct {
	Enabled   bool              `mapstructure:"enabled"`
	Heartbeat SimpleEventConfig `mapstructure:"heartbeat"`
	EMCY      SimpleEventConfig `mapstructure:"emcy"`
	// SDO passively observes standard client/server SDO traffic. It does not
	// initiate transfers; active polling is a separate future capability.
	SDO  SDOSniffConfig `mapstructure:"sdo"`
	PDOs []PDOConfig    `mapstructure:"pdos"`
}

func (s *SniffConfig) validate() error {
	if !s.Enabled {
		return nil
	}
	if err := s.Heartbeat.validate("sniff.heartbeat"); err != nil {
		return err
	}
	if err := s.EMCY.validate("sniff.emcy"); err != nil {
		return err
	}
	if err := s.SDO.validate(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(s.PDOs))
	cobIDs := make(map[uint32]struct{}, len(s.PDOs))
	for i := range s.PDOs {
		if err := s.PDOs[i].validate(); err != nil {
			return err
		}
		if _, dup := seen[s.PDOs[i].Name]; dup {
			return fmt.Errorf("sniff.pdos: duplicate pdo name %q", s.PDOs[i].Name)
		}
		seen[s.PDOs[i].Name] = struct{}{}
		if _, dup := cobIDs[s.PDOs[i].CobID]; dup {
			return fmt.Errorf("sniff.pdos: duplicate cob_id 0x%X", s.PDOs[i].CobID)
		}
		cobIDs[s.PDOs[i].CobID] = struct{}{}
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

// Config is the configuration for the CANopen receiver.
type Config struct {
	// Interface is the SocketCAN interface name (e.g. "can0", "vcan0").
	Interface string `mapstructure:"interface"`

	// ReadTimeout bounds how long a single frame receive may block; it also
	// governs how quickly Shutdown can interrupt the read loop. Defaults
	// applied in CreateDefaultConfig.
	ReadTimeout time.Duration `mapstructure:"read_timeout"`

	Metrics MetricsConfig `mapstructure:"metrics"`
	Logs    LogsConfig    `mapstructure:"logs"`

	Sniff SniffConfig `mapstructure:"sniff"`
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
	if !cfg.Sniff.Enabled {
		return errors.New("sniff must be enabled")
	}
	if err := cfg.Sniff.validate(); err != nil {
		return err
	}

	// Cross-check: any signal requesting metrics emission requires
	// metrics.enabled, and any signal requesting logs emission requires
	// logs.enabled, so misconfiguration fails fast instead of silently
	// dropping data.
	var checkEmit func(scope string, e EmitMode) error
	checkEmit = func(scope string, e EmitMode) error {
		if e.emitsMetrics() && !cfg.Metrics.Enabled {
			return fmt.Errorf("%s: emit %q requires metrics.enabled=true", scope, e)
		}
		if e.emitsLogs() && !cfg.Logs.Enabled {
			return fmt.Errorf("%s: emit %q requires logs.enabled=true", scope, e)
		}
		return nil
	}
	if cfg.Sniff.Heartbeat.Emit != "" {
		if err := checkEmit("sniff.heartbeat", cfg.Sniff.Heartbeat.Emit); err != nil {
			return err
		}
	}
	if cfg.Sniff.EMCY.Emit != "" {
		if err := checkEmit("sniff.emcy", cfg.Sniff.EMCY.Emit); err != nil {
			return err
		}
	}
	if cfg.Sniff.SDO.Emit != "" {
		if err := checkEmit("sniff.sdo", cfg.Sniff.SDO.Emit); err != nil {
			return err
		}
	}
	for _, pdo := range cfg.Sniff.PDOs {
		for _, sig := range pdo.Signals {
			if err := checkEmit(fmt.Sprintf("pdo %q signal %q", pdo.Name, sig.Name), sig.Emit); err != nil {
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
		Sniff: SniffConfig{
			Enabled: true,
		},
	}
}
