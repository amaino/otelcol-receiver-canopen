// Package cantransport provides an abstraction over a CAN bus connection so
// the receiver's sniffing logic can be tested without real hardware,
// and so platform-specific SocketCAN code is isolated behind a small
// interface.
package cantransport

import (
	"context"
	"errors"
	"time"
)

// Frame is a classic CAN frame (max 8 data bytes). CAN FD is out of scope.
type Frame struct {
	ID       uint32 // 11-bit or 29-bit arbitration ID (no RTR/error flags)
	Extended bool
	Data     []byte
}

// ErrClosed is returned by Recv/Send once the connection has been closed.
var ErrClosed = errors.New("cantransport: connection closed")

// Conn is a CAN bus connection: a duplex stream of frames.
type Conn interface {
	// Recv blocks until a frame is available, ctx is done, or the connection
	// is closed, whichever happens first.
	Recv(ctx context.Context) (Frame, error)
	// Send transmits a frame, blocking until it is queued or ctx is done.
	Send(ctx context.Context, f Frame) error
	// Close releases the underlying resources. Safe to call more than once.
	Close() error
}

// Dialer opens a Conn for a named CAN interface (e.g. "can0").
type Dialer interface {
	Dial(ctx context.Context, iface string) (Conn, error)
}

// DialTimeout is the default timeout applied when establishing the
// underlying socket/link, independent of any read/write deadlines.
const DialTimeout = 5 * time.Second
