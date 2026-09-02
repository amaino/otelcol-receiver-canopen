// Package sniffer classifies and decodes passively observed CANopen frames:
// PDOs configured for decoding, heartbeat/NMT state changes, and EMCY
// emergency messages.
package sniffer

import (
	"fmt"

	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/emit"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/sdoobserver"
)

// Function codes (high 4 bits of an 11-bit standard COB-ID), per CiA 301.
const (
	FuncNMT       = 0x000
	FuncSync      = 0x080
	FuncEmergency = 0x080 // node-specific: 0x080 + node id (1..127); 0x080 itself is SYNC
	FuncTPDO1     = 0x180
	FuncRPDO1     = 0x200
	FuncTPDO2     = 0x280
	FuncRPDO2     = 0x300
	FuncTPDO3     = 0x380
	FuncRPDO3     = 0x400
	FuncTPDO4     = 0x480
	FuncRPDO4     = 0x500
	FuncSDOTx     = 0x580
	FuncSDORx     = 0x600
	FuncHeartbeat = 0x700
)

// NMTState is a CANopen NMT device state as broadcast in a heartbeat frame.
type NMTState uint8

const (
	StateBootup         NMTState = 0x00
	StateStopped        NMTState = 0x04
	StateOperational    NMTState = 0x05
	StatePreOperational NMTState = 0x7F
)

func (s NMTState) String() string {
	switch s {
	case StateBootup:
		return "bootup"
	case StateStopped:
		return "stopped"
	case StateOperational:
		return "operational"
	case StatePreOperational:
		return "pre-operational"
	default:
		return fmt.Sprintf("unknown(0x%02X)", uint8(s))
	}
}

// PDOSignal binds a decoded value's destination (metric or log) to its
// SignalConfig-derived decode parameters. Kept independent of the receiver
// package's config types so this package has no import cycle; the receiver
// builds these from config.
type PDOSignal struct {
	Name       string
	BitOffset  int
	Type       codec.DataType
	ByteLen    int
	Scale      float64
	Offset     float64
	Unit       string
	EmitMetric bool
	EmitLog    bool
	MetricSum  bool // false = gauge
	Attributes map[string]string
}

// PDODef is a configured PDO (fixed COB-ID) with its signals to decode.
type PDODef struct {
	Name    string
	CobID   uint32
	Signals []PDOSignal
}

// SDOFilter selects passively observed SDO frames. Unset fields are wildcards.
type SDOFilter struct {
	NodeID   *uint8
	Index    *uint16
	SubIndex *uint8
}

// Config is the subset of receiver configuration the Sniffer needs,
// expressed in terms independent of the top-level config package.
type Config struct {
	InterfaceName       string
	PDOs                map[uint32]PDODef // keyed by CobID
	HeartbeatEmitMetric bool
	HeartbeatEmitLog    bool
	EMCYEmitMetric      bool
	EMCYEmitLog         bool
	SDOEmitMetric       bool
	SDOEmitLog          bool
	SDOFilters          []SDOFilter
}

// Sniffer classifies and decodes frames according to Config, appending
// results to the given metrics/logs builders.
type Sniffer struct {
	cfg Config

	// nmtState tracks the last known state per node id, to detect changes
	// and avoid re-emitting logs for repeated identical heartbeats when only
	// state-change logging is desired. Metrics are still updated every time.
	nmtState map[uint8]NMTState
	sdo      *sdoobserver.Observer
}

// New creates a Sniffer for the given configuration.
func New(cfg Config) *Sniffer {
	return &Sniffer{cfg: cfg, nmtState: make(map[uint8]NMTState), sdo: sdoobserver.New()}
}

// HandleFrame classifies and decodes a single received frame, appending any
// resulting metric/log data to the builders. Malformed or irrelevant frames
// are ignored (the caller may count them for diagnostics).
func (s *Sniffer) HandleFrame(f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	if f.Extended {
		// This receiver only classifies the standard 11-bit CANopen COB-ID
		// space; extended-ID traffic is left to future work.
		return
	}

	if pdo, ok := s.cfg.PDOs[f.ID]; ok {
		s.handlePDO(pdo, f, metrics, logs)
		return
	}

	funcCode := f.ID &^ 0x7F
	nodeID := uint8(f.ID & 0x7F)

	switch funcCode {
	case FuncHeartbeat:
		s.handleHeartbeat(nodeID, f, metrics, logs)
	case FuncEmergency:
		if nodeID != 0 {
			s.handleEMCY(nodeID, f, logs, metrics)
		}
	case FuncSDOTx:
		if nodeID != 0 {
			s.handleSDO(nodeID, sdoobserver.ServerToClient, f, metrics, logs)
		}
	case FuncSDORx:
		if nodeID != 0 {
			s.handleSDO(nodeID, sdoobserver.ClientToServer, f, metrics, logs)
		}
	}
}

func (s *Sniffer) resourceAttrs() map[string]string {
	return map[string]string{"canopen.interface": s.cfg.InterfaceName}
}

func (s *Sniffer) handlePDO(pdo PDODef, f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	for _, sig := range pdo.Signals {
		v, err := codec.Decode(f.Data, sig.Type, sig.BitOffset, sig.ByteLen)
		if err != nil {
			continue // malformed/short frame for this signal; skip silently
		}
		value := codec.ApplyScale(v, sig.Scale, sig.Offset)
		attrs := s.resourceAttrs()
		if sig.EmitMetric && metrics != nil {
			kind := emit.KindGauge
			if sig.MetricSum {
				kind = emit.KindSum
			}
			metrics.Add(emit.MetricPoint{
				ResourceAttrs: attrs,
				Name:          sig.Name,
				Unit:          sig.Unit,
				Kind:          kind,
				Value:         value,
				Attributes:    sig.Attributes,
			})
		}
		if sig.EmitLog && logs != nil {
			logAttrs := map[string]any{
				"canopen.pdo.name":     pdo.Name,
				"canopen.signal.name":  sig.Name,
				"canopen.signal.value": value,
			}
			for k, v := range sig.Attributes {
				logAttrs[k] = v
			}
			logs.Add(emit.LogRecord{
				ResourceAttrs: attrs,
				Severity:      plog.SeverityNumberInfo,
				Body:          fmt.Sprintf("canopen pdo %s signal %s = %v", pdo.Name, sig.Name, value),
				Attributes:    logAttrs,
			})
		}
	}
}

func (s *Sniffer) handleHeartbeat(nodeID uint8, f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	if len(f.Data) < 1 {
		return
	}
	state := NMTState(f.Data[0])
	prev, known := s.nmtState[nodeID]
	changed := !known || prev != state
	s.nmtState[nodeID] = state

	attrs := s.resourceAttrs()
	attrs["canopen.node_id"] = fmt.Sprintf("%d", nodeID)

	if s.cfg.HeartbeatEmitMetric && metrics != nil {
		metrics.Add(emit.MetricPoint{
			ResourceAttrs: attrs,
			Name:          "canopen.node.nmt_state",
			Kind:          emit.KindGauge,
			Value:         float64(state),
		})
	}
	if s.cfg.HeartbeatEmitLog && logs != nil && changed {
		logs.Add(emit.LogRecord{
			ResourceAttrs: attrs,
			Severity:      plog.SeverityNumberInfo,
			Body:          fmt.Sprintf("canopen node %d NMT state changed to %s", nodeID, state),
			Attributes: map[string]any{
				"canopen.node_id":   int(nodeID),
				"canopen.nmt_state": state.String(),
			},
		})
	}
}

// emcyErrorCodeDescriptions covers the CiA 301 generic error code ranges
// (high byte of the emergency error code); device-specific codes above
// 0xFF00 are reported numerically without a description.
func emcyErrorCodeDescription(code uint16) string {
	switch {
	case code == 0x0000:
		return "error reset / no error"
	case code>>8 == 0x10:
		return "generic error"
	case code>>8 == 0x20:
		return "current"
	case code>>8 == 0x30:
		return "voltage"
	case code>>8 == 0x40:
		return "temperature"
	case code>>8 == 0x50:
		return "device hardware"
	case code>>8 == 0x60:
		return "device software"
	case code>>8 == 0x70:
		return "additional modules"
	case code>>8 == 0x80:
		return "monitoring"
	case code>>8 == 0x90:
		return "external error"
	case code>>8 == 0xF0:
		return "additional functions"
	case code>>8 == 0xFF:
		return "device specific"
	default:
		return "unknown"
	}
}

func (s *Sniffer) handleEMCY(nodeID uint8, f cantransport.Frame, logs *emit.LogsBuilder, metrics *emit.MetricsBuilder) {
	if len(f.Data) < 3 {
		return
	}
	errCode := uint16(f.Data[0]) | uint16(f.Data[1])<<8
	errReg := f.Data[2]

	attrs := s.resourceAttrs()
	attrs["canopen.node_id"] = fmt.Sprintf("%d", nodeID)

	if s.cfg.EMCYEmitMetric && metrics != nil {
		metrics.Add(emit.MetricPoint{
			ResourceAttrs: attrs,
			Name:          "canopen.node.emcy_error_register",
			Kind:          emit.KindGauge,
			Value:         float64(errReg),
		})
	}
	if s.cfg.EMCYEmitLog && logs != nil {
		sev := plog.SeverityNumberWarn
		if errCode == 0 {
			sev = plog.SeverityNumberInfo
		}
		logs.Add(emit.LogRecord{
			ResourceAttrs: attrs,
			Severity:      sev,
			Body: fmt.Sprintf(
				"canopen node %d emergency: code=0x%04X (%s) register=0x%02X",
				nodeID, errCode, emcyErrorCodeDescription(errCode), errReg,
			),
			Attributes: map[string]any{
				"canopen.node_id":         int(nodeID),
				"canopen.emcy.error_code": int(errCode),
				"canopen.emcy.register":   int(errReg),
			},
		})
	}
}

// handleSDO observes, but never participates in, SDO frames exchanged by
// other CANopen devices on the bus. It emits only completed transfers and
// aborts, after reconstructing segmented payloads where required.
func (s *Sniffer) handleSDO(nodeID uint8, direction sdoobserver.Direction, f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	event, err := s.sdo.Observe(nodeID, direction, f.Data)
	if err != nil || event == nil || !s.matchesSDOFilter(event.NodeID, event.Index, event.SubIndex) {
		return
	}
	attrs := s.resourceAttrs()
	attrs["canopen.node_id"] = fmt.Sprintf("%d", event.NodeID)
	eventAttrs := map[string]string{
		"canopen.sdo.direction": string(event.Direction),
		"canopen.sdo.operation": event.Operation,
		"canopen.sdo.index":     fmt.Sprintf("0x%04X", event.Index),
		"canopen.sdo.subindex":  fmt.Sprintf("0x%02X", event.SubIndex),
	}
	logAttrs := map[string]any{
		"canopen.node_id":       int(event.NodeID),
		"canopen.sdo.direction": string(event.Direction),
		"canopen.sdo.operation": event.Operation,
		"canopen.sdo.index":     int(event.Index),
		"canopen.sdo.subindex":  int(event.SubIndex),
		"canopen.sdo.data":      fmt.Sprintf("%X", event.Data),
	}
	if event.AbortCode != nil {
		eventAttrs["canopen.sdo.abort_code"] = fmt.Sprintf("0x%08X", *event.AbortCode)
		logAttrs["canopen.sdo.abort_code"] = fmt.Sprintf("0x%08X", *event.AbortCode)
	}
	if s.cfg.SDOEmitMetric && metrics != nil {
		metrics.Add(emit.MetricPoint{
			ResourceAttrs: attrs,
			Name:          "canopen.sdo.transfers",
			Kind:          emit.KindSum,
			Value:         1,
			Attributes:    eventAttrs,
		})
	}
	if s.cfg.SDOEmitLog && logs != nil {
		logs.Add(emit.LogRecord{
			ResourceAttrs: attrs,
			Severity:      plog.SeverityNumberInfo,
			Body:          fmt.Sprintf("canopen SDO %s %s on node %d (0x%04X:%02X)", event.Direction, event.Operation, event.NodeID, event.Index, event.SubIndex),
			Attributes:    logAttrs,
		})
	}
}

func (s *Sniffer) matchesSDOFilter(nodeID uint8, index uint16, subIndex uint8) bool {
	if len(s.cfg.SDOFilters) == 0 {
		return true
	}
	for _, filter := range s.cfg.SDOFilters {
		if filter.NodeID != nil && *filter.NodeID != nodeID {
			continue
		}
		if filter.Index != nil && *filter.Index != index {
			continue
		}
		if filter.SubIndex != nil && *filter.SubIndex != subIndex {
			continue
		}
		return true
	}
	return false
}
