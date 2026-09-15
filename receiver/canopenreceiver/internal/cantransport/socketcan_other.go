//go:build !linux

package cantransport

import (
	"context"
	"fmt"
	"runtime"
)

// socketCANDialer is a stub used on non-Linux platforms, where SocketCAN is
// unavailable. This keeps the receiver buildable and its config/codec/emit
// logic testable everywhere, while failing fast and clearly at Start time on
// unsupported platforms.
type socketCANDialer struct{}

// NewDialer returns a Dialer that always fails to dial on non-Linux
// platforms, since SocketCAN is a Linux-only kernel subsystem.
func NewDialer() Dialer {
	return socketCANDialer{}
}

func (socketCANDialer) Dial(_ context.Context, iface string) (Conn, error) {
	return nil, fmt.Errorf(
		"cantransport: SocketCAN is only supported on Linux (GOOS=%s), cannot dial interface %q",
		runtime.GOOS, iface,
	)
}
