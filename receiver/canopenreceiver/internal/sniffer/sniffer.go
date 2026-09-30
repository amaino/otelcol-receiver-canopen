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

// Field binds a decoded value's destination (metric or log) to its
// FieldConfig-derived decode parameters. Kept independent of the receiver
// package's config types so this package has no import cycle; the receiver
// builds these from config.
type Field struct {
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
	Attributes map[string]any
}

// PDODef is a configured PDO (fixed COB-ID) with its fields to decode.
type PDODef struct {
	Name   string
	CobID  uint32
	Fields []Field
}

// SDOObjectDef identifies one SDO object (node/index/sub-index) and its
// fields to decode from the completed transfer payload. Multiple Fields
// decode a struct from one object.
type SDOObjectDef struct {
	NodeID   uint8
	Index    uint16
	SubIndex uint8
	Fields   []Field
}

// SDOChannel identifies one configured SDO client/server COB-ID pair.
type SDOChannel struct {
	NodeID              uint8
	ClientToServerCobID uint32
	ServerToClientCobID uint32
}

// RawMatch is a byte-equality condition used to discriminate between
// multiple raw message shapes sharing one COB-ID.
type RawMatch struct {
	ByteOffset int
	Value      uint8
}

// RawMessageDef declares a decodable field layout for raw frames on a given
// COB-ID, optionally narrowed by Match conditions (all ANDed).
type RawMessageDef struct {
	Name   string
	Match  []RawMatch
	Fields []Field
}

func (d RawMessageDef) matches(data []byte) bool {
	for _, m := range d.Match {
		if m.ByteOffset >= len(data) || data[m.ByteOffset] != m.Value {
			return false
		}
	}
	return true
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
	SDOObjects          []SDOObjectDef
	SDOChannels         []SDOChannel
	// RawEmitMetric/RawEmitLog control emission for frames matched by
	// RawCobIDs. When a matching COB-ID has one or more RawMessages
	// entries whose Match conditions are satisfied, the frame is decoded
	// into named fields instead of being emitted as an undifferentiated
	// hex payload.
	RawEmitMetric bool
	RawEmitLog    bool
	RawCobIDs     map[uint32]struct{}
	RawMessages   map[uint32][]RawMessageDef // keyed by CobID
}

// Sniffer classifies and decodes frames according to Config, appending
// results to the given metrics/logs builders.
type Sniffer struct {
	cfg Config

	// nmtState tracks the last known state per node id, to detect changes
	// and avoid re-emitting logs for repeated identical heartbeats when only
	// state-change logging is desired. Metrics are still updated every time.
	nmtState   map[uint8]NMTState
	sdo        *sdoobserver.Observer
	sdoByCobID map[uint32]sdoChannel
}

type sdoChannel struct {
	nodeID      uint8
	key         uint32
	clientCobID uint32
}

// New creates a Sniffer for the given configuration.
func New(cfg Config) *Sniffer {
	s := &Sniffer{cfg: cfg, nmtState: make(map[uint8]NMTState), sdo: sdoobserver.New(), sdoByCobID: make(map[uint32]sdoChannel)}
	if len(cfg.SDOChannels) == 0 {
		return s
	}
	for _, channel := range cfg.SDOChannels {
		entry := sdoChannel{nodeID: channel.NodeID, key: channel.ClientToServerCobID, clientCobID: channel.ClientToServerCobID}
		s.sdoByCobID[channel.ClientToServerCobID] = entry
		s.sdoByCobID[channel.ServerToClientCobID] = entry
	}
	return s
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

	if _, ok := s.cfg.RawCobIDs[f.ID]; ok {
		s.handleRaw(f, metrics, logs)
		return
	}

	if pdo, ok := s.cfg.PDOs[f.ID]; ok {
		s.handlePDO(pdo, f, metrics, logs)
		return
	}

	if channel, ok := s.sdoByCobID[f.ID]; ok {
		direction := sdoobserver.ClientToServer
		if f.ID == channel.clientCobID {
			direction = sdoobserver.ClientToServer
		} else {
			direction = sdoobserver.ServerToClient
		}
		s.handleSDO(channel.key, channel.nodeID, direction, f, metrics, logs)
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
			s.handleSDO(f.ID-0x580, nodeID, sdoobserver.ServerToClient, f, metrics, logs)
		}
	case FuncSDORx:
		if nodeID != 0 {
			s.handleSDO(f.ID-0x600, nodeID, sdoobserver.ClientToServer, f, metrics, logs)
		}
	}
}

func (s *Sniffer) resourceAttrs() map[string]string {
	return map[string]string{"canopen.interface": s.cfg.InterfaceName}
}

// handleRaw emits a matched frame. If the CobID has one or more RawMessages
// whose Match conditions are satisfied by this frame, it is decoded into
// named signals (reusing the PDO signal codec) exactly like a PDO. Otherwise
// it falls back to an undifferentiated hex dump, with no protocol decoding.
// Used to capture vendor/proprietary traffic (e.g. non-CANopen service-tool
// protocols riding on the bus) for structured emission or, when no field
// layout is declared, later separate decoding.
func (s *Sniffer) handleRaw(f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	for _, msg := range s.cfg.RawMessages[f.ID] {
		if msg.matches(f.Data) {
			s.handleRawMessage(msg, f, metrics, logs)
			return
		}
	}
	attrs := s.resourceAttrs()
	attrs["canopen.cob_id"] = fmt.Sprintf("0x%03X", f.ID)
	eventAttrs := map[string]any{
		"canopen.raw.data": fmt.Sprintf("%X", f.Data),
	}
	logAttrs := map[string]any{
		"canopen.cob_id":   fmt.Sprintf("0x%03X", f.ID),
		"canopen.raw.data": fmt.Sprintf("%X", f.Data),
	}
	if s.cfg.RawEmitMetric && metrics != nil {
		metrics.Add(emit.MetricPoint{
			ResourceAttrs: attrs,
			Name:          "canopen.raw.frames",
			Kind:          emit.KindSum,
			Value:         1,
			Attributes:    eventAttrs,
		})
	}
	if s.cfg.RawEmitLog && logs != nil {
		logs.Add(emit.LogRecord{
			ResourceAttrs: attrs,
			Severity:      plog.SeverityNumberInfo,
			Body:          fmt.Sprintf("canopen raw frame on 0x%03X: %X", f.ID, f.Data),
			Attributes:    logAttrs,
		})
	}
}

// emitFields decodes and emits every field in fields from data. Metrics are
// emitted per field, one instrument each, exactly as before. Logs are
// grouped: if any field requests logs, exactly one log record is emitted for
// the whole group. A single logged field uses its decoded value directly as
// the body; multiple logged fields use one map body keyed by field name.
// contextAttrs/body identify the source (a PDO, raw message, or SDO object)
// and are added once.
func (s *Sniffer) emitFields(fields []Field, data []byte, resourceAttrs map[string]string, contextAttrs map[string]any, body string, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	bodyMap := make(map[string]any, len(fields))
	logAttrs := make(map[string]any, len(contextAttrs))
	for k, v := range contextAttrs {
		logAttrs[k] = v
	}
	haveLog := false
	for _, field := range fields {
		v, err := codec.Decode(data, field.Type, field.BitOffset, field.ByteLen)
		if err != nil {
			continue // malformed/short frame for this field; skip silently
		}
		if field.EmitMetric && metrics != nil {
			kind := emit.KindGauge
			if field.MetricSum {
				kind = emit.KindSum
			}
			metrics.Add(emit.MetricPoint{
				ResourceAttrs: resourceAttrs,
				Name:          field.Name,
				Unit:          field.Unit,
				Kind:          kind,
				Value:         codec.ApplyScale(v, field.Scale, field.Offset),
				Attributes:    field.Attributes,
			})
		}
		if field.EmitLog && logs != nil {
			haveLog = true
			bodyMap[field.Name] = v.BodyValue(field.Scale, field.Offset)
			for k, attr := range field.Attributes {
				logAttrs[k] = attr
			}
		}
	}
	if haveLog {
		record := emit.LogRecord{
			ResourceAttrs: resourceAttrs,
			Severity:      plog.SeverityNumberInfo,
			Body:          body,
			Attributes:    logAttrs,
		}
		if len(bodyMap) == 1 {
			for _, value := range bodyMap {
				record.BodyValue = value
			}
		} else {
			record.BodyMap = bodyMap
		}
		logs.Add(record)
	}
}

// handleRawMessage decodes a raw frame's declared fields, exactly like
// handlePDO, so fixed-layout vendor protocols don't need a bespoke
// processor.
func (s *Sniffer) handleRawMessage(msg RawMessageDef, f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	attrs := s.resourceAttrs()
	attrs["canopen.cob_id"] = fmt.Sprintf("0x%03X", f.ID)
	s.emitFields(msg.Fields, f.Data, attrs,
		map[string]any{"canopen.raw.message": msg.Name},
		fmt.Sprintf("canopen raw message %s decoded", msg.Name),
		metrics, logs)
}

func (s *Sniffer) handlePDO(pdo PDODef, f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	attrs := s.resourceAttrs()
	s.emitFields(pdo.Fields, f.Data, attrs,
		map[string]any{"canopen.pdo.name": pdo.Name},
		fmt.Sprintf("canopen pdo %s decoded", pdo.Name),
		metrics, logs)
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
// aborts, after reconstructing segmented payloads where required. Only
// explicitly declared SDOObjects are decoded/emitted - there is no generic
// undecoded fallback; declare the object's fields to see its data.
func (s *Sniffer) handleSDO(channelKey uint32, nodeID uint8, direction sdoobserver.Direction, f cantransport.Frame, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	event, err := s.sdo.ObserveOnChannel(channelKey, nodeID, direction, f.Data)
	if err != nil || event == nil {
		return
	}
	s.emitTypedSDO(*event, metrics, logs)
}

func (s *Sniffer) emitTypedSDO(event sdoobserver.Event, metrics *emit.MetricsBuilder, logs *emit.LogsBuilder) {
	if event.AbortCode != nil {
		return
	}
	for _, object := range s.cfg.SDOObjects {
		if object.NodeID != event.NodeID || object.Index != event.Index || object.SubIndex != event.SubIndex {
			continue
		}
		attrs := s.resourceAttrs()
		attrs["canopen.node_id"] = fmt.Sprintf("%d", event.NodeID)
		attrs["canopen.sdo.index"] = fmt.Sprintf("0x%04X", event.Index)
		attrs["canopen.sdo.subindex"] = fmt.Sprintf("0x%02X", event.SubIndex)
		contextAttrs := map[string]any{
			"canopen.node_id":       int(event.NodeID),
			"canopen.sdo.index":     int(event.Index),
			"canopen.sdo.subindex":  int(event.SubIndex),
			"canopen.sdo.direction": string(event.Direction),
			"canopen.sdo.operation": event.Operation,
		}
		body := fmt.Sprintf("canopen SDO object 0x%04X:%02X decoded", event.Index, event.SubIndex)
		s.emitFields(object.Fields, event.Data, attrs, contextAttrs, body, metrics, logs)
	}
}
