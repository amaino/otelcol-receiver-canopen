package canopenreceiver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/cantransport"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/emit"
	"github.com/amaino/otelcol-receiver-canopen/receiver/canopenreceiver/internal/sniffer"
)

// canopenReceiver implements receiver.Metrics and receiver.Logs by sharing a
// single underlying CAN connection and dispatch loop. The factory hands out
// the same instance to both signal consumers so there is exactly one
// connection to the bus regardless of which signals are enabled.
type canopenReceiver struct {
	cfg      *Config
	settings receiver.Settings
	dialer   cantransport.Dialer

	metricsConsumer consumer.Metrics
	logsConsumer    consumer.Logs

	sniff *sniffer.Sniffer

	metricsBuilder *emit.MetricsBuilder
	logsBuilder    *emit.LogsBuilder
	buildersMu     sync.Mutex

	conn   cantransport.Conn
	cancel context.CancelFunc
	wg     sync.WaitGroup

	startOnce    sync.Once
	shutdownOnce sync.Once
	startErr     error
}

func newCanopenReceiver(cfg *Config, set receiver.Settings, dialer cantransport.Dialer) *canopenReceiver {
	r := &canopenReceiver{
		cfg:            cfg,
		settings:       set,
		dialer:         dialer,
		metricsBuilder: emit.NewMetricsBuilder(),
		logsBuilder:    emit.NewLogsBuilder(),
	}
	r.sniff = sniffer.New(buildSnifferConfig(cfg))
	return r
}

func buildSnifferConfig(cfg *Config) sniffer.Config {
	sc := sniffer.Config{
		InterfaceName:       cfg.Interface,
		PDOs:                make(map[uint32]sniffer.PDODef),
		HeartbeatEmitMetric: cfg.Sniff.Heartbeat.Emit.emitsMetrics(),
		HeartbeatEmitLog:    cfg.Sniff.Heartbeat.Emit.emitsLogs(),
		EMCYEmitMetric:      cfg.Sniff.EMCY.Emit.emitsMetrics(),
		EMCYEmitLog:         cfg.Sniff.EMCY.Emit.emitsLogs(),
		SDOEmitMetric:       cfg.Sniff.SDO.Emit.emitsMetrics(),
		SDOEmitLog:          cfg.Sniff.SDO.Emit.emitsLogs(),
		SDOFilters:          make([]sniffer.SDOFilter, 0, len(cfg.Sniff.SDO.Filters)),
	}
	if !cfg.Sniff.Enabled {
		return sc
	}
	for _, filter := range cfg.Sniff.SDO.Filters {
		sc.SDOFilters = append(sc.SDOFilters, sniffer.SDOFilter{
			NodeID:   filter.NodeID,
			Index:    filter.Index,
			SubIndex: filter.SubIndex,
		})
	}
	for _, pdo := range cfg.Sniff.PDOs {
		def := sniffer.PDODef{Name: pdo.Name, CobID: pdo.CobID}
		for _, sig := range pdo.Signals {
			def.Signals = append(def.Signals, sniffer.PDOSignal{
				Name:       sig.Name,
				BitOffset:  sig.BitOffset,
				Type:       sig.Type,
				ByteLen:    sig.ByteLen,
				Scale:      sig.Scale,
				Offset:     sig.Offset,
				Unit:       sig.Unit,
				EmitMetric: sig.Emit.emitsMetrics(),
				EmitLog:    sig.Emit.emitsLogs(),
				MetricSum:  sig.MetricType == MetricSum,
				Attributes: sig.Attributes,
			})
		}
		sc.PDOs[pdo.CobID] = def
	}
	return sc
}

func (r *canopenReceiver) Start(ctx context.Context, _ component.Host) error {
	r.startOnce.Do(func() {
		r.startErr = r.doStart(ctx)
	})
	return r.startErr
}

func (r *canopenReceiver) doStart(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, cantransport.DialTimeout)
	defer cancel()
	conn, err := r.dialer.Dial(dialCtx, r.cfg.Interface)
	if err != nil {
		return fmt.Errorf("canopenreceiver: failed to open interface %q: %w", r.cfg.Interface, err)
	}
	r.conn = conn

	runCtx, runCancel := context.WithCancel(context.Background())
	r.cancel = runCancel

	r.wg.Add(1)
	go r.dispatchLoop(runCtx)

	if r.cfg.Metrics.Enabled {
		r.wg.Add(1)
		go r.metricsFlushLoop(runCtx)
	}

	return nil
}

func (r *canopenReceiver) Shutdown(ctx context.Context) error {
	var shutdownErr error
	r.shutdownOnce.Do(func() {
		shutdownErr = r.doShutdown(ctx)
	})
	return shutdownErr
}

func (r *canopenReceiver) doShutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.conn != nil {
		_ = r.conn.Close()
	}
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Flush anything remaining so shutdown doesn't silently drop the last
	// interval of data.
	r.flushMetrics(ctx)
	r.flushLogs(ctx)
	return nil
}

// dispatchLoop is the single reader of the shared Conn, routing every frame
// to the sniffer.
func (r *canopenReceiver) dispatchLoop(ctx context.Context) {
	defer r.wg.Done()
	logger := r.settings.Logger
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		recvCtx, cancel := context.WithTimeout(ctx, r.cfg.ReadTimeout)
		f, err := r.conn.Recv(recvCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if err == context.DeadlineExceeded {
				continue
			}
			if err == cantransport.ErrClosed {
				return
			}
			logger.Warn("canopen: frame receive error", zap.Error(err))
			continue
		}

		r.buildersMu.Lock()
		r.sniff.HandleFrame(f, r.metricsIfEnabled(), r.logsIfEnabled())
		r.buildersMu.Unlock()
	}
}

func (r *canopenReceiver) metricsIfEnabled() *emit.MetricsBuilder {
	if r.cfg.Metrics.Enabled {
		return r.metricsBuilder
	}
	return nil
}

func (r *canopenReceiver) logsIfEnabled() *emit.LogsBuilder {
	if r.cfg.Logs.Enabled {
		return r.logsBuilder
	}
	return nil
}

func (r *canopenReceiver) metricsFlushLoop(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cfg.Metrics.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.flushMetrics(ctx)
			r.flushLogs(ctx)
		}
	}
}

func (r *canopenReceiver) flushMetrics(ctx context.Context) {
	if r.metricsConsumer == nil {
		return
	}
	r.buildersMu.Lock()
	if r.metricsBuilder.Empty() {
		r.buildersMu.Unlock()
		return
	}
	md := r.metricsBuilder.Emit()
	r.buildersMu.Unlock()
	if err := r.metricsConsumer.ConsumeMetrics(ctx, md); err != nil {
		r.settings.Logger.Error("canopen: failed to consume metrics", zap.Error(err))
	}
}

func (r *canopenReceiver) flushLogs(ctx context.Context) {
	if r.logsConsumer == nil {
		return
	}
	r.buildersMu.Lock()
	if r.logsBuilder.Empty() {
		r.buildersMu.Unlock()
		return
	}
	ld := r.logsBuilder.Emit()
	r.buildersMu.Unlock()
	if err := r.logsConsumer.ConsumeLogs(ctx, ld); err != nil {
		r.settings.Logger.Error("canopen: failed to consume logs", zap.Error(err))
	}
}
