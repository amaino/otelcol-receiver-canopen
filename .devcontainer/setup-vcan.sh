#!/usr/bin/env bash
# Sets up a virtual CAN (vcan0) interface for local development and testing,
# so the receiver and canopen-publisher tool can be exercised without real
# CAN hardware. Safe to re-run.
set -euo pipefail

IFACE="${1:-vcan0}"

if ! lsmod | grep -q '^vcan'; then
    echo "Loading vcan kernel module..."
    sudo modprobe vcan || {
        echo "WARNING: failed to load vcan module. If running in Docker Desktop" >&2
        echo "(Windows/Mac), the host Linux VM may already have it, or this" >&2
        echo "container may need --privileged / a compatible kernel." >&2
    }
fi

if ip link show "$IFACE" >/dev/null 2>&1; then
    echo "$IFACE already exists."
else
    echo "Creating $IFACE..."
    sudo ip link add dev "$IFACE" type vcan
fi

sudo ip link set up "$IFACE"
ip link show "$IFACE"
echo "vcan interface '$IFACE' is up."
