package canopenreceiver

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	channels := make(map[uint8]SDOChannelConfig, len(receiver.cfg.Sniff.SDO.Channels))
	for _, channel := range receiver.cfg.Sniff.SDO.Channels {
		channels[channel.NodeID] = channel
	}
	return &sdoPoller{
		receiver: receiver,
		ctx:      ctx,
		objects:  receiver.cfg.Sniff.SDO.Poll.Objects,
		channels: channels,
	}
}

func (p *sdoPoller) run() {
	defer p.receiver.wg.Done()
	for {
		for _, object := range p.objects {
			p.pollUntilSuccess(object)
		}
		if p.receiver.cfg.Sniff.SDO.Poll.Mode != "interval" {
			return
		}
		if !waitContext(p.ctx, p.receiver.cfg.Sniff.SDO.Poll.Interval) {
			return
		}
	}
}

func (p *sdoPoller) pollUntilSuccess(object SDOObjectConfig) bool {
	settings := p.receiver.cfg.Sniff.SDO.Poll
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
		if p.poll(object) {
			return true
		}
		if !settings.Retry || (settings.MaxRetries != nil && attempt >= *settings.MaxRetries) {
			return false
		}
		attempt++
		if !waitContext(p.ctx, backoff) {
			return false
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (p *sdoPoller) poll(object SDOObjectConfig) bool {
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
		return false
	}
	timeout := p.receiver.cfg.Sniff.SDO.Poll.Timeout
	if timeout == 0 {
		timeout = defaultSDOPollTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-active.result:
		return result.ok
	case <-timer.C:
		return false
	case <-p.ctx.Done():
		return false
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
