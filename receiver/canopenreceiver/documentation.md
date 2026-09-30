# canopenreceiver emitted telemetry

This documents the telemetry this receiver produces automatically, in
addition to whatever user-configured fields (`pdo[].fields[]`,
`sdo.sniff.objects[].fields[]`, `raw.sniff.messages[].fields[]`) are
emitted under their configured names.

All metrics and logs share a resource with attribute `canopen.interface`
(the configured SocketCAN interface name), plus `canopen.node_id` when the
event is attributable to a specific node.

## Metrics

### `canopen.node.nmt_state`

- **Type**: gauge (unitless integer NMT state code)
- **Enabled by**: `heartbeat.metrics: true`
- **Attributes (resource)**: `canopen.interface`, `canopen.node_id`
- **Value**: raw NMT state byte from the heartbeat frame (`0x00` bootup,
  `0x04` stopped, `0x05` operational, `0x7F` pre-operational).
- Emitted on every heartbeat frame, not just on state changes.

### `canopen.node.emcy_error_register`

- **Type**: gauge (unitless)
- **Enabled by**: `emcy.metrics: true`
- **Attributes (resource)**: `canopen.interface`, `canopen.node_id`
- **Value**: the CiA 301 error register byte from the EMCY frame.
- Emitted on every EMCY frame.

### `canopen.raw.frames`

- **Type**: non-monotonic cumulative sum; one point with value `1` per
  captured raw frame.
- **Enabled by**: `raw.sniff.metrics: true`, for a COB-ID listed in
  `raw.sniff.cob_ids`.
- **Attributes (resource)**: `canopen.interface`, `canopen.cob_id`.
- **Attributes (point)**: `canopen.raw.data` (uppercase hexadecimal payload).
- No protocol decoding is performed. This exists to capture non-CANopen or
  vendor-proprietary traffic sharing the bus (e.g. a service-tool protocol)
  so it can be decoded by a separate, downstream component.

### User-configured metrics (`sdo.sniff.objects[]`, `pdo[].fields[]`, `raw.sniff.messages[].fields[]`)

- **Type**: gauge or sum (per field's `metric_type`), named by the field's
  `name`.
- **Enabled by**: the individual field's `metrics: true`. Not supported for
  `bytes`/`visible_string` fields.
- Multiple SDO channels can be configured on the same CAN interface. Each
  channel specifies its node ID and client/server COB-ID pair. Configured
  COB-IDs may use nonstandard assignments; they are only required to be
  valid standard 11-bit CAN IDs and unique across the configured channels.
- There is no generic undecoded fallback for SDO transfers - only
  explicitly declared `sdo.sniff.objects[]`/`sdo.poll.objects[]` are ever
  emitted; any object's structure (including a multi-field struct) can
  always be declared precisely.

### Declarative raw message decoding (`raw.sniff.messages[]`)

- For fixed-layout vendor frames, `raw.sniff.messages[]` decodes named
  fields directly (same semantics as `pdo[].fields[]`: type, bit offset,
  scale/offset, unit, `metrics`, `logs`, `metric_type`, `attributes`)
  instead of emitting opaque raw hex, so a bespoke downstream processor is
  often unnecessary.
- Each message may declare `match[]` byte-equality conditions (ANDed) to
  discriminate its shape from other messages sharing the same COB-ID, such
  as a vendor command word echoed at the start of the payload. A message
  with no `match[]` matches every frame on its `cob_id`.
- Decoded fields are emitted as metrics/logs under their own configured
  name, following the same emission rules as PDO fields — not as
  `canopen.raw.frames` / raw hex.
- If a frame's COB-ID has declared messages but none of them match, the
  frame falls back to the generic raw-hex capture (`canopen.raw.frames` /
  raw-frame log) described above, when `raw.sniff.metrics`/`raw.sniff.logs`
  is set.
- Declaring a message automatically enables raw capture on its `cob_id`;
  it does not need to also appear in `raw.sniff.cob_ids[]`.

## Logs

### Heartbeat / NMT state changes

- **Enabled by**: `heartbeat.logs: true`
- **Emitted**: only when a node's NMT state changes (not on every
  heartbeat), to avoid flooding logs on a node that stays in one state.
- **Severity**: Info
- **Attributes**: `canopen.node_id` (int), `canopen.nmt_state` (string, e.g.
  `"operational"`).

### EMCY (emergency) messages

- **Enabled by**: `emcy.logs: true`
- **Emitted**: on every EMCY frame.
- **Severity**: Warn (Info if the error code is `0x0000`, i.e. "error
  reset/no error").
- **Attributes**: `canopen.node_id` (int), `canopen.emcy.error_code` (int),
  `canopen.emcy.register` (int). The log body includes a human-readable
  description of the CiA 301 error code category.

### User-configured field logs (PDO/SDO object/raw message/raw transaction)

- **Enabled by**: at least one field in the group having `logs: true`.
- **Emitted**: once per matched frame/completed SDO transfer, combining
  every field in that group with `logs: true` into a **single** structured
  log record - not one record per field. Aborted SDO transfers produce no
  emission (there's no data to decode).
- **Severity**: Info
- **Body**: the decoded field value directly when exactly one field is logged;
  when multiple fields are logged, a structured map keyed by each field's
  `name` (the same identifier used for its metric, if any) is used. Values are
  a hex string for `bytes`, the string itself for `visible_string`, or the
  scaled numeric value otherwise.
- **Attributes**: context metadata only, never the decoded values -
  `canopen.pdo.name` (PDO), `canopen.node_id`/`canopen.sdo.index`/
  `canopen.sdo.subindex`/`canopen.sdo.direction`/`canopen.sdo.operation`
  (SDO object), or `canopen.raw.message` (raw message) - plus every field's
  static `attributes:`, merged in.

### Raw frame capture

- **Enabled by**: `raw.sniff.metrics` / `raw.sniff.logs`, for a COB-ID listed
  in `raw.sniff.cob_ids`.
- **Emitted**: once per matched frame, with no protocol interpretation.
- **Severity**: Info
- **Attributes**: `canopen.cob_id` (hex string), `canopen.raw.data`
  (uppercase hexadecimal payload).
