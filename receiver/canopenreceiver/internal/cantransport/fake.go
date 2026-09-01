package cantransport

import (
	"context"
	"sync"
)

// FakeBus is an in-memory CAN bus used for tests. Frames sent by one
// connection are broadcast to all other connections on the same bus,
// mimicking a real CAN bus, and frames injected via Inject are delivered to
// every connection as if received from the wire.
type FakeBus struct {
	mu     sync.Mutex
	conns  []*fakeConn
	closed bool
}

// NewFakeBus creates an empty fake bus.
func NewFakeBus() *FakeBus {
	return &FakeBus{}
}

// Dial creates a new connection attached to the bus. iface is ignored.
func (b *FakeBus) Dial(_ context.Context, _ string) (Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := &fakeConn{
		bus:  b,
		rx:   make(chan Frame, 256),
		done: make(chan struct{}),
	}
	b.conns = append(b.conns, c)
	return c, nil
}

// Inject delivers f to every connection currently dialed on the bus, as if
// it had arrived from an external CAN node (e.g. simulating another device's
// CAN frame or a sniffed PDO).
func (b *FakeBus) Inject(f Frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		c.deliver(f)
	}
}

func (b *FakeBus) broadcast(from *fakeConn, f Frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		if c != from {
			c.deliver(f)
		}
	}
}

func (b *FakeBus) forget(c *fakeConn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, existing := range b.conns {
		if existing == c {
			b.conns = append(b.conns[:i], b.conns[i+1:]...)
			break
		}
	}
}

type fakeConn struct {
	bus       *FakeBus
	rx        chan Frame
	closeOnce sync.Once
	done      chan struct{}
}

func (c *fakeConn) deliver(f Frame) {
	select {
	case c.rx <- f:
	case <-c.done:
	default:
		// Drop the frame if the receiver isn't keeping up, mirroring a real
		// bus/socket buffer overflow rather than blocking the sender.
	}
}

func (c *fakeConn) Recv(ctx context.Context) (Frame, error) {
	select {
	case f, ok := <-c.rx:
		if !ok {
			return Frame{}, ErrClosed
		}
		return f, nil
	case <-c.done:
		return Frame{}, ErrClosed
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	}
}

func (c *fakeConn) Send(ctx context.Context, f Frame) error {
	select {
	case <-c.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	c.bus.broadcast(c, f)
	return nil
}

func (c *fakeConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.bus.forget(c)
	})
	return nil
}
