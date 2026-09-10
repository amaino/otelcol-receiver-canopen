# otelcol-receiver-canopen

An OpenTelemetry Collector receiver for CANopen over SocketCAN, enabling
telemetry collection through passive traffic sniffing and active SDO
requests.

The project is designed around a flexible Collector configuration model: a
shared base collector config is combined with one or more deployment-specific
profile files. This allows a standard CANopen setup to coexist with private,
platform-specific protocol channels in a clean and maintainable way.

## Status

This repository is being built up incrementally, in a small number of
reviewable steps:

1. **This commit** — a bare OpenTelemetry Collector distribution (built via
   the [OpenTelemetry Collector Builder](https://github.com/open-telemetry/opentelemetry-collector/tree/main/cmd/builder))
   with just the standard OTLP receiver/exporter, plus the devcontainer, CI,
   and build tooling that the rest of the project will build on. No
   CANopen-specific code exists yet.
2. **Next** — the `canopen` receiver, supporting only passive traffic
   sniffing (PDO/EMCY/heartbeat decoding into metrics/logs).
3. **After that** — active SDO request support, including periodic polling.

## What's here

- [`builder-config.yaml`](./builder-config.yaml) — builds a complete
  Collector distribution (`otelcol-canopen`), combining core processors and
  exporters with whatever receivers exist so far.
- [`config/example-collector.yaml`](./config/example-collector.yaml) — an
  example pipeline for the current distribution.
- [`.devcontainer`](./.devcontainer) — a dev container (works on Windows,
  macOS, and Linux) with a `vcan0` virtual CAN interface set up
  automatically, so the whole stack can be developed and tested without a
  physical CAN bus, once the CANopen receiver exists.
- [`.github/workflows/ci.yaml`](./.github/workflows/ci.yaml) — CI that
  builds the `otelcol-canopen` distribution via ocb.

See [docs/running-on-device.md](./docs/running-on-device.md) for build/run
instructions.

## Configuration model

The Collector supports multiple config files on the command line, and they are
merged into a single in-memory configuration before validation. This is the
recommended pattern for this project:

```sh
./dist/otelcol-canopen \
  --config=file:config/base-collector.yaml \
  --config=file:config/vehicle-profile.yaml
```

This keeps collector plumbing separate from device-specific traffic rules.

### Standard CANopen settings

The standard CANopen portion is expressed in the same shape as the receiver
already supports:

```yaml
receivers:
  canopen:
    interface: ${env:CANOPEN_INTERFACE:-can0}
    sniff:
      enabled: true
      heartbeat:
        emit: logs
      emcy:
        emit: logs
      sdo:
        emit: logs
        filters:
          - node_id: 11
            index: 0x2009
            sub_index: 0x05
      pdos:
        - name: traction_tpdo
          cob_id: 0x188
          signals:
            - name: traction.speed
              bit_offset: 0
              type: int16
              scale: 0.1
              unit: rpm
              emit: logs
```

This section is used for standard CANopen traffic, including heartbeat/NMT,
EMCY, passive SDO observation, and user-defined PDO decoding.

### Private/proprietary channels

Some deployments do not use only standard CANopen. They also carry private,
request/response protocol traffic on dedicated CAN IDs. The config should
therefore allow an explicit channel list for those messages without conflating
those definitions with standard PDO or SDO decoding:

```yaml
receivers:
  canopen:
    sniff:
      channels:
        - name: controller_service
          request_cob_id: 0x51E
          response_cob_id: 0x49E
          decoder: controller_service
          emit: logs
```

This is intentionally generic. `channels` describes the bus wiring and the
logical message group; `decoder` selects the protocol-specific parsing logic for
that channel. The standard CANopen subset remains clean and portable, while the
private protocol is isolated in its own config block.

This structure makes the project suitable for both:
- standard, open CANopen traffic inspection
- private, deployment-specific message decoding using a companion decoder or
  private configuration profile

### Why this split matters

The generic collector should not pretend to understand every proprietary
protocol by default. Instead, the config separates:

- standard CANopen rules (`sdo`, `pdos`, heartbeat, EMCY)
- vehicle-specific private channels (`channels`)
- deployment-specific profile selection using multiple `--config` files

This keeps the project flexible and avoids hard-coding private protocol details
into the public base configuration.

## Quick start

```sh
make build-device
./dist/otelcol-canopen --config=config/base-collector.yaml --config=config/vehicle-profile.yaml
```

The example config files in this repository are intentionally split so the
Collector can be reused across different deployments without rewriting the core
OTel pipeline setup.
