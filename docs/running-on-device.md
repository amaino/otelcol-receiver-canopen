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

## Running against a real vehicle platform

For real deployments, the collector config is split into a shared base file
plus a platform-specific profile, merged via multiple `--config` arguments
(each file can be a full or partial config; the Collector deep-merges them):

```sh
./dist/otelcol-canopen \
  --config=config/base-collector.yaml \
  --config=config/vehicle-profile.yaml   # or config/vehicle-profile-alt.yaml
```

- [`config/base-collector.yaml`](../config/base-collector.yaml) — OTLP
  receiver, processors, exporters, extensions, pipelines, and the CANopen
  receiver's generic settings (interface, heartbeat/EMCY sniffing). The
  interface defaults to `can0`; override with the `CANOPEN_INTERFACE`
  environment variable (e.g. `vcan0` for local testing).
- [`config/vehicle-profile.yaml`](../config/vehicle-profile.yaml) /
  [`config/vehicle-profile-alt.yaml`](../config/vehicle-profile-alt.yaml) — per-platform
  `sniff.sdo.filters`, listing only the standard CiA-301 SDO objects known to
  be exchanged at startup for parameter/version verification on that
  platform. Proprietary vendor protocols (e.g. TRUCKCOM) are out of scope
  for this receiver and are not represented here.

## Roadmap

- **Next commit**: add the `canopen` receiver with passive traffic sniffing
  (PDO/EMCY/heartbeat decoding) only.
- **After that**: add active SDO polling support.

See the top-level [README.md](../README.md) for the overall plan.
