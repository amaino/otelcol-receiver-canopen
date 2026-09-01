FROM mcr.microsoft.com/devcontainers/go:1-1.25-bookworm

# can-utils gives us candump/cansend/cangen for manual poking at vcan0;
# iproute2 provides `ip link` to create/bring up the vcan interface;
# kmod lets postCreate try to load the vcan kernel module if it isn't
# already built into the host kernel.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        can-utils \
        iproute2 \
        kmod \
    && rm -rf /var/lib/apt/lists/*
