# Building and running the collector on a device

This starting point produces a real `otelcol-canopen` binary using the
[OpenTelemetry Collector Builder](https://github.com/open-telemetry/opentelemetry-collector/tree/main/cmd/builder)
(ocb), configured in [`builder-config.yaml`](../builder-config.yaml).

This distribution includes the standard OTLP receiver/exporter, the
passive-only `canopen` receiver, `batch`/`memory_limiter` processors, and a
`zpages` extension. Active SDO polling is deliberately not included yet.

## Build

```sh
make build-device
# produces ./dist/otelcol-canopen
```

## Run

```sh
./dist/otelcol-canopen --config=config/example-collector.yaml
```

This starts OTLP receivers on `4317` (gRPC) / `4318` (HTTP), and a CANopen
sniffer on `vcan0`. It forwards everything to `debug` (stdout) plus an
upstream OTLP endpoint (configurable via `OTLP_EXPORTER_ENDPOINT`, default
`localhost:4317`).

## Testing without hardware

Open this repo in the provided [dev container](../.devcontainer) (works on
Windows, macOS, and Linux) to get a `vcan0` virtual CAN interface set up
automatically. In another terminal, run:

```sh
make run-publisher
```

This publishes heartbeat, TPDO, and optionally EMCY traffic which the
example collector configuration will decode and export.

## Roadmap

- **Next commit**: add active SDO polling support.

See the top-level [README.md](../README.md) for the overall plan.
