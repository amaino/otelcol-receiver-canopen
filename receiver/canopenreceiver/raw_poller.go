package canopenreceiver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/codec"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/emit"
)

const (
	defaultRawTransactionTimeout    = 2 * time.Second
	defaultRawTransactionBackoff    = time.Second
	defaultRawTransactionMaxBackoff = time.Minute
)

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
	onceCompleted := make([]bool, len(p.transactions))
	for {
		hasRecurringTransaction := false
		for index, transaction := range p.transactions {
			if transaction.effectiveMode() == "once" {
				if onceCompleted[index] {
					continue
				}
				p.poll(transaction)
				onceCompleted[index] = true
				continue
			}
			hasRecurringTransaction = true
			p.poll(transaction)
			if !waitContext(p.ctx, transaction.Interval) {
				return
			}
		}
		if !hasRecurringTransaction {
			return
		}
	}
}

func (p *rawTransactionPoller) poll(transaction RawTransactionConfig) {
	attempt := 0
	backoff := transaction.Backoff
	if backoff == 0 {
		backoff = defaultRawTransactionBackoff
	}
	maxBackoff := transaction.MaxBackoff
	if maxBackoff == 0 {
		maxBackoff = defaultRawTransactionMaxBackoff
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	for {
		attempt++
		err := p.pollOnce(transaction)
		if err == nil {
			if attempt > 1 {
				p.receiver.settings.Logger.Info("canopen: raw transaction recovered after retry",
					zap.String("transaction", transaction.Name),
					zap.Uint32("request_cob_id", transaction.CobID),
					zap.Uint32("response_cob_id", transaction.Response.CobID),
					zap.Int("attempts", attempt),
				)
			}
			return
		}
		if p.ctx.Err() != nil {
			return
		}
		retriesRemain := transaction.MaxRetries == nil || attempt-1 < *transaction.MaxRetries
		if !transaction.Retry || !retriesRemain {
			failureMessage := "canopen: raw transaction failed"
			if transaction.Retry {
				failureMessage = "canopen: raw transaction failed; retry limit reached"
			} else {
				failureMessage = "canopen: raw transaction failed; retries disabled"
			}
			p.receiver.settings.Logger.Warn(failureMessage,
				zap.String("transaction", transaction.Name),
				zap.Uint32("request_cob_id", transaction.CobID),
				zap.Uint32("response_cob_id", transaction.Response.CobID),
				zap.Int("attempts", attempt),
				zap.Bool("retry_enabled", transaction.Retry),
				zap.Error(err),
			)
			return
		}
		p.receiver.settings.Logger.Warn("canopen: raw transaction attempt failed; retry scheduled",
			zap.String("transaction", transaction.Name),
			zap.Uint32("request_cob_id", transaction.CobID),
			zap.Uint32("response_cob_id", transaction.Response.CobID),
			zap.Int("attempt", attempt),
			zap.Int("retry", attempt),
			zap.Duration("retry_delay", backoff),
			zap.Error(err),
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

func (p *rawTransactionPoller) pollOnce(transaction RawTransactionConfig) error {
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
		return fmt.Errorf("send request: %w", err)
	}
	timeout := transaction.Timeout
	if timeout == 0 {
		timeout = defaultRawTransactionTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-active.result:
		return nil
	case <-timer.C:
		return fmt.Errorf("response timed out after %s", timeout)
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *rawTransactionPoller) handleFrame(frame cantransport.Frame) bool {
	p.mu.Lock()
	active := p.active
	if active == nil || frame.Extended || frame.ID != active.transaction.Response.CobID || !rawTransactionMatches(active.transaction.Response.Match, frame.Data) {
		p.mu.Unlock()
		return false
	}
	p.active = nil
	p.mu.Unlock()

	p.receiver.emitRawTransaction(active.transaction, frame)
	select {
	case active.result <- true:
	default:
	}
	return true
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
