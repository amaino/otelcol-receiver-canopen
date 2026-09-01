//go:build linux

package cantransport

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.einride.tech/can"
	"go.einride.tech/can/pkg/socketcan"
)

// zeroTime is the zero value used to clear a previously set read deadline.
var zeroTime time.Time

// socketCANDialer dials real Linux SocketCAN interfaces.
type socketCANDialer struct{}

// NewDialer returns a Dialer that connects to SocketCAN interfaces on Linux.
func NewDialer() Dialer {
	return socketCANDialer{}
}

func (socketCANDialer) Dial(ctx context.Context, iface string) (Conn, error) {
	conn, err := socketcan.DialContext(ctx, "can", iface)
	if err != nil {
		return nil, fmt.Errorf("cantransport: dial %s: %w", iface, err)
	}
	return newSocketCANConn(conn), nil
}

type socketCANConn struct {
	conn net.Conn
	recv *socketcan.Receiver
	tx   *socketcan.Transmitter
}

func newSocketCANConn(conn net.Conn) *socketCANConn {
	return &socketCANConn{
		conn: conn,
		recv: socketcan.NewReceiver(conn),
		tx:   socketcan.NewTransmitter(conn),
	}
}

func (c *socketCANConn) Recv(ctx context.Context) (Frame, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return Frame{}, fmt.Errorf("cantransport: set read deadline: %w", err)
		}
	} else {
		// Clear any previously set deadline for a blocking read.
		if err := c.conn.SetReadDeadline(zeroTime); err != nil {
			return Frame{}, fmt.Errorf("cantransport: clear read deadline: %w", err)
		}
	}
	if !c.recv.Receive() {
		if err := c.recv.Err(); err != nil {
			return Frame{}, fmt.Errorf("cantransport: receive: %w", err)
		}
		return Frame{}, ErrClosed
	}
	f := c.recv.Frame()
	data := make([]byte, f.Length)
	copy(data, f.Data[:f.Length])
	return Frame{ID: f.ID, Extended: f.IsExtended, Data: data}, nil
}

func (c *socketCANConn) Send(ctx context.Context, f Frame) error {
	msg := can.Frame{ID: f.ID, IsExtended: f.Extended, Length: uint8(len(f.Data))}
	copy(msg.Data[:], f.Data)
	if err := c.tx.TransmitFrame(ctx, msg); err != nil {
		return fmt.Errorf("cantransport: send: %w", err)
	}
	return nil
}

func (c *socketCANConn) Close() error {
	return c.conn.Close()
}
