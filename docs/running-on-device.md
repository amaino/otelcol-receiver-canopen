# Building and running the collector on a device

This starting point produces a real `otelcol-canopen` binary using the
[OpenTelemetry Collector Builder](https://github.com/open-telemetry/opentelemetry-collector/tree/main/cmd/builder)
(ocb), configured in [`builder-config.yaml`](../builder-config.yaml).

At this stage the distribution only contains the standard OTLP
receiver/exporter plus `batch`/`memory_limiter` processors and a `zpages`
extension — no CANopen-specific code exists yet. This lets us validate the
whole build/test/devcontainer/CI pipeline before adding CANopen support in
later commits.

## Build

```sh
make build-device
# produces ./dist/otelcol-canopen
```

## Run

```sh
./dist/otelcol-canopen --config=config/example-collector.yaml
```

This starts an OTLP receiver on `4317` (gRPC) / `4318` (HTTP) and forwards
everything to `debug` (stdout) plus an upstream OTLP endpoint (configurable
via `OTLP_EXPORTER_ENDPOINT`, default `localhost:4317`).

## Testing without hardware

Open this repo in the provided [dev container](../.devcontainer) (works on
Windows, macOS, and Linux) to get a `vcan0` virtual CAN interface set up
automatically — this will be used once the CANopen receiver is added.

## Roadmap

- **Next commit**: add the `canopen` receiver with passive traffic sniffing
  (PDO/EMCY/heartbeat decoding) only.
- **After that**: add active SDO polling support.

See the top-level [README.md](../README.md) for the overall plan.
