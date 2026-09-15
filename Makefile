.PHONY: build test vet fmt fmt-check lint tidy vcan-up run-publisher build-device

## Core Go targets

build:
	go build ./...

test:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; echo "$$out"; exit 1; \
	fi

lint: fmt-check vet

tidy:
	go mod tidy

## Local vcan testing (Linux only; use the devcontainer on Windows/macOS)

vcan-up:
	bash .devcontainer/setup-vcan.sh vcan0

run-publisher:
	go run ./cmd/canopen-publisher -iface=vcan0

## Device build via the OpenTelemetry Collector Builder (ocb)

build-device:
	go run go.opentelemetry.io/collector/cmd/builder@v0.159.0 --config=builder-config.yaml
