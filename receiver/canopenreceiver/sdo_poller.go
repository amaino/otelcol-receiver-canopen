package canopenreceiver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
)

const (
	defaultSDOPollTimeout    = 2 * time.Second
	defaultSDOPollBackoff    = time.Second
	defaultSDOPollMaxBackoff = time.Minute
)

type sdoPollResult struct {
	ok  bool
	err error
}

type activeSDOPoll struct {
	object      SDOObjectConfig
	serverCobID uint32
	segment     bool
	toggle      bool
	result      chan sdoPollResult
}

type sdoPoller struct {
	receiver *canopenReceiver
	ctx      context.Context
	objects  []SDOObjectConfig
	channels map[uint8]SDOChannelConfig

	mu     sync.Mutex
	active *activeSDOPoll
}

func newSDOPoller(receiver *canopenReceiver, ctx context.Context) *sdoPoller {
	channels := make(map[uint8]SDOChannelConfig, len(receiver.cfg.SDO.Sniff.Channels))
	for _, channel := range receiver.cfg.SDO.Sniff.Channels {
		channels[channel.NodeID] = channel
	}
	return &sdoPoller{
		receiver: receiver,
		ctx:      ctx,
		objects:  receiver.cfg.SDO.Poll.Objects,
		channels: channels,
	}
}

func (p *sdoPoller) run() {
	defer p.receiver.wg.Done()
	for {
		for _, object := range p.objects {
			p.pollUntilSuccess(object)
		}
		if p.receiver.cfg.SDO.Poll.Mode != "interval" {
			return
		}
		if !waitContext(p.ctx, p.receiver.cfg.SDO.Poll.Interval) {
			return
		}
	}
}

func (p *sdoPoller) pollUntilSuccess(object SDOObjectConfig) {
	settings := p.receiver.cfg.SDO.Poll
	attempt := 0
	backoff := settings.Backoff
	if backoff == 0 {
		backoff = defaultSDOPollBackoff
	}
	maxBackoff := settings.MaxBackoff
	if maxBackoff == 0 {
		maxBackoff = defaultSDOPollMaxBackoff
	}
	for {
		attempt++
		result := p.poll(object)
		if result.ok {
			if attempt > 1 {
				p.receiver.settings.Logger.Info("canopen: SDO poll recovered after retry",
					zap.Uint("node_id", uint(object.NodeID)),
					zap.Uint("index", uint(object.Index)),
					zap.Uint("sub_index", uint(object.SubIndex)),
					zap.Int("attempts", attempt),
				)
			}
			return
		}
		if p.ctx.Err() != nil {
			return
		}
		retriesRemain := settings.MaxRetries == nil || attempt-1 < *settings.MaxRetries
		if !settings.Retry || !retriesRemain {
			failureMessage := "canopen: SDO poll failed; retries disabled"
			if settings.Retry {
				failureMessage = "canopen: SDO poll failed; retry limit reached"
			}
			p.receiver.settings.Logger.Warn(failureMessage,
				zap.Uint("node_id", uint(object.NodeID)),
				zap.Uint("index", uint(object.Index)),
				zap.Uint("sub_index", uint(object.SubIndex)),
				zap.Int("attempts", attempt),
				zap.Bool("retry_enabled", settings.Retry),
				zap.Error(result.err),
			)
			return
		}
		p.receiver.settings.Logger.Warn("canopen: SDO poll attempt failed; retry scheduled",
			zap.Uint("node_id", uint(object.NodeID)),
			zap.Uint("index", uint(object.Index)),
			zap.Uint("sub_index", uint(object.SubIndex)),
			zap.Int("attempt", attempt),
			zap.Int("retry", attempt),
			zap.Duration("retry_delay", backoff),
			zap.Error(result.err),
		)
		if !waitContext(p.ctx, backoff) {
			return
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (p *sdoPoller) poll(object SDOObjectConfig) sdoPollResult {
	channel, ok := p.channels[object.NodeID]
	if !ok {
		channel = SDOChannelConfig{
			NodeID:              object.NodeID,
			ClientToServerCobID: 0x600 + uint32(object.NodeID),
			ServerToClientCobID: 0x580 + uint32(object.NodeID),
		}
	}
	request := cantransport.Frame{
		ID:   channel.ClientToServerCobID,
		Data: []byte{0x40, byte(object.Index), byte(object.Index >> 8), object.SubIndex, 0, 0, 0, 0},
	}
	active := &activeSDOPoll{
		object:      object,
		serverCobID: channel.ServerToClientCobID,
		result:      make(chan sdoPollResult, 1),
	}
	p.mu.Lock()
	p.active = active
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active = nil
		p.mu.Unlock()
	}()

	if err := p.receiver.sendPollFrame(p.ctx, request); err != nil {
		return sdoPollResult{err: fmt.Errorf("send request: %w", err)}
	}
	timeout := p.receiver.cfg.SDO.Poll.Timeout
	if timeout == 0 {
		timeout = defaultSDOPollTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-active.result:
		return result
	case <-timer.C:
		return sdoPollResult{err: fmt.Errorf("response timed out after %s", timeout)}
	case <-p.ctx.Done():
		return sdoPollResult{err: p.ctx.Err()}
	}
}

func (p *sdoPoller) handleFrame(frame cantransport.Frame) {
	p.mu.Lock()
	active := p.active
	if active == nil || frame.Extended || frame.ID != active.serverCobID {
		p.mu.Unlock()
		return
	}
	data := frame.Data
	if len(data) == 0 {
		p.mu.Unlock()
		return
	}
	if data[0] == 0x80 {
		if len(data) < 4 {
			p.mu.Unlock()
			return
		}
		index := uint16(data[1]) | uint16(data[2])<<8
		if index != active.object.Index || data[3] != active.object.SubIndex {
			p.mu.Unlock()
			return
		}
		p.finishLocked(active, false, fmt.Errorf("SDO abort for 0x%04X:%02X", active.object.Index, active.object.SubIndex))
		p.mu.Unlock()
		return
	}
	if !active.segment {
		if len(data) < 4 || uint16(data[1])|uint16(data[2])<<8 != active.object.Index || data[3] != active.object.SubIndex {
			p.mu.Unlock()
			return
		}
		if data[0]&0x02 != 0 {
			p.finishLocked(active, true, nil)
			p.mu.Unlock()
			return
		}
		active.segment = true
		active.toggle = false
	} else {
		if data[0]&0x10 != boolByte(active.toggle) {
			p.finishLocked(active, false, fmt.Errorf("unexpected SDO segment toggle"))
			p.mu.Unlock()
			return
		}
		if data[0]&0x01 != 0 {
			p.finishLocked(active, true, nil)
			p.mu.Unlock()
			return
		}
		active.toggle = !active.toggle
	}
	request := cantransport.Frame{ID: 0x600 + uint32(active.object.NodeID), Data: []byte{0x60 | boolByte(active.toggle), 0, 0, 0, 0, 0, 0, 0}}
	if channel, ok := p.channels[active.object.NodeID]; ok {
		request.ID = channel.ClientToServerCobID
	}
	_ = p.receiver.sendPollFrame(p.ctx, request)
	p.mu.Unlock()
}

func (p *sdoPoller) finishLocked(active *activeSDOPoll, ok bool, err error) {
	select {
	case active.result <- sdoPollResult{ok: ok, err: err}:
	default:
	}
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func boolByte(value bool) byte {
	if value {
		return 0x10
	}
	return 0
}
