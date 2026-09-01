# otelcol-receiver-canopen

An OpenTelemetry Collector receiver for CANopen over SocketCAN, enabling
telemetry collection through passive traffic sniffing and active SDO
requests.

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

## Quick start

```sh
make build-device
./dist/otelcol-canopen --config=config/example-collector.yaml
```
