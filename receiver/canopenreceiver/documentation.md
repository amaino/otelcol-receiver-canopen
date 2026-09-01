# canopenreceiver emitted telemetry

This documents the telemetry this receiver produces automatically, in
addition to whatever user-configured signals (`sniff.pdos[].signals[]`) are
emitted under their configured names.

All metrics and logs share a resource with attribute `canopen.interface`
(the configured SocketCAN interface name), plus `canopen.node_id` when the
event is attributable to a specific node.

## Metrics

### `canopen.node.nmt_state`

- **Type**: gauge (unitless integer NMT state code)
- **Enabled by**: `sniff.heartbeat.emit: metrics` or `both`
- **Attributes (resource)**: `canopen.interface`, `canopen.node_id`
- **Value**: raw NMT state byte from the heartbeat frame (`0x00` bootup,
  `0x04` stopped, `0x05` operational, `0x7F` pre-operational).
- Emitted on every heartbeat frame, not just on state changes.

### `canopen.node.emcy_error_register`

- **Type**: gauge (unitless)
- **Enabled by**: `sniff.emcy.emit: metrics` or `both`
- **Attributes (resource)**: `canopen.interface`, `canopen.node_id`
- **Value**: the CiA 301 error register byte from the EMCY frame.
- Emitted on every EMCY frame.

### `canopen.sdo.transfers`

- **Type**: non-monotonic cumulative sum; one point with value `1` per
  passively observed completed SDO transfer or abort.
- **Enabled by**: `sniff.sdo.emit: metrics` or `both`
- **Attributes (resource)**: `canopen.interface`, `canopen.node_id`
- **Attributes (point)**: `canopen.sdo.direction`
  (`client_to_server` or `server_to_client`), `canopen.sdo.command`, and,
  for initiation/abort frames, `canopen.sdo.index` and
  `canopen.sdo.subindex`. Abort responses also carry
  `canopen.sdo.abort_code`.
- Supports expedited and segmented upload/download transfers. The receiver is
  only an observer: it does not send or respond to SDO frames.
- `sniff.sdo.filters` can restrict emission by node ID, object index, and
  sub-index. Frames match when they satisfy any configured filter.

## Logs

### Heartbeat / NMT state changes

- **Enabled by**: `sniff.heartbeat.emit: logs` or `both`
- **Emitted**: only when a node's NMT state changes (not on every
  heartbeat), to avoid flooding logs on a node that stays in one state.
- **Severity**: Info
- **Attributes**: `canopen.node_id` (int), `canopen.nmt_state` (string, e.g.
  `"operational"`).

### EMCY (emergency) messages

- **Enabled by**: `sniff.emcy.emit: logs` or `both`
- **Emitted**: on every EMCY frame.
- **Severity**: Warn (Info if the error code is `0x0000`, i.e. "error
  reset/no error").
- **Attributes**: `canopen.node_id` (int), `canopen.emcy.error_code` (int),
  `canopen.emcy.register` (int). The log body includes a human-readable
  description of the CiA 301 error code category.

### SDO traffic

- **Enabled by**: `sniff.sdo.emit: logs` or `both`
- **Emitted**: once when a standard expedited or segmented SDO transfer
  completes, or when an SDO abort is observed. Client frames use
  `0x600 + node ID`; server frames use `0x580 + node ID`.
- **Severity**: Info
- **Attributes**: `canopen.node_id` (int), `canopen.sdo.direction`,
  `canopen.sdo.operation` (`upload`, `download`, or `abort`), index/subindex,
  and `canopen.sdo.data` (uppercase hexadecimal payload). Abort responses
  additionally include `canopen.sdo.abort_code`.
- This is passive observability of traffic between other CANopen devices; it
  neither sends SDO requests nor registers an SDO server.

### User-configured PDO signal logs

- **Enabled by**: the individual signal's `emit: logs` or `both`.
- **Severity**: Info
- **Attributes**: `canopen.signal.name`, `canopen.signal.value`,
  `canopen.pdo.name`, plus any user-configured `attributes`.
