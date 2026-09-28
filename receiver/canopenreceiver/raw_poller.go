package canopenreceiver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/emit"
)

const defaultRawTransactionTimeout = 2 * time.Second

type activeRawTransaction struct {
	transaction RawTransactionConfig
	result      chan bool
}

type rawTransactionPoller struct {
	receiver     *canopenReceiver
	ctx          context.Context
	transactions []RawTransactionConfig

	mu     sync.Mutex
	active *activeRawTransaction
}

func newRawTransactionPoller(receiver *canopenReceiver, ctx context.Context) *rawTransactionPoller {
	return &rawTransactionPoller{
		receiver:     receiver,
		ctx:          ctx,
		transactions: receiver.cfg.Raw.Transactions,
	}
}

func (p *rawTransactionPoller) run() {
	defer p.receiver.wg.Done()
	for {
		for _, transaction := range p.transactions {
			p.poll(transaction)
			if !waitContext(p.ctx, transaction.Interval) {
				return
			}
		}
		if len(p.transactions) == 0 {
			return
		}
	}
}

func (p *rawTransactionPoller) poll(transaction RawTransactionConfig) {
	active := &activeRawTransaction{transaction: transaction, result: make(chan bool, 1)}
	p.mu.Lock()
	p.active = active
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.active == active {
			p.active = nil
		}
		p.mu.Unlock()
	}()

	request := cantransport.Frame{ID: transaction.CobID, Data: append([]byte(nil), transaction.Payload...)}
	if err := p.receiver.sendFrame(p.ctx, request); err != nil {
		return
	}
	timeout := transaction.Timeout
	if timeout == 0 {
		timeout = defaultRawTransactionTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-active.result:
	case <-timer.C:
	case <-p.ctx.Done():
	}
}

func (p *rawTransactionPoller) handleFrame(frame cantransport.Frame) {
	p.mu.Lock()
	active := p.active
	if active == nil || frame.Extended || frame.ID != active.transaction.Response.CobID || !rawTransactionMatches(active.transaction.Response.Match, frame.Data) {
		p.mu.Unlock()
		return
	}
	p.active = nil
	p.mu.Unlock()

	p.receiver.emitRawTransaction(active.transaction, frame)
	select {
	case active.result <- true:
	default:
	}
}

func rawTransactionMatches(matches []RawMatchByte, data []byte) bool {
	for _, match := range matches {
		if match.ByteOffset >= len(data) || data[match.ByteOffset] != match.Value {
			return false
		}
	}
	return true
}

func (r *canopenReceiver) emitRawTransaction(transaction RawTransactionConfig, frame cantransport.Frame) {
	r.buildersMu.Lock()
	defer r.buildersMu.Unlock()
	resourceAttrs := map[string]string{"canopen.interface": r.cfg.Interface}
	resourceAttrs["canopen.cob_id"] = fmt.Sprintf("0x%03X", frame.ID)
	bodyMap := make(map[string]any, len(transaction.Response.Fields))
	logAttrs := map[string]any{"canopen.raw.transaction": transaction.Name}
	for _, field := range transaction.Response.Fields {
		value, err := codec.Decode(frame.Data, field.Type, field.BitOffset, field.ByteLen)
		if err != nil {
			continue
		}
		if field.Metrics && r.metricsIfEnabled() != nil {
			kind := emit.KindGauge
			if field.MetricType == MetricSum {
				kind = emit.KindSum
			}
			r.metricsBuilder.Add(emit.MetricPoint{
				ResourceAttrs: resourceAttrs,
				Name:          field.Name,
				Unit:          field.Unit,
				Kind:          kind,
				Value:         codec.ApplyScale(value, field.Scale, field.Offset),
				Attributes:    field.Attributes,
			})
		}
		if field.Logs && r.logsIfEnabled() != nil {
			bodyMap[field.Name] = value.BodyValue(field.Scale, field.Offset)
			for key, attr := range field.Attributes {
				logAttrs[key] = attr
			}
		}
	}
	if len(bodyMap) == 0 || r.logsIfEnabled() == nil {
		return
	}
	record := emit.LogRecord{
		ResourceAttrs: resourceAttrs,
		Severity:      plog.SeverityNumberInfo,
		Body:          fmt.Sprintf("canopen raw transaction %s decoded", transaction.Name),
		Attributes:    logAttrs,
	}
	if len(bodyMap) == 1 {
		for _, value := range bodyMap {
			record.BodyValue = value
		}
	} else {
		record.BodyMap = bodyMap
	}
	r.logsBuilder.Add(record)
}
