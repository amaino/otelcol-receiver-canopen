// Command canopen-publisher periodically transmits CANopen traffic on a
// SocketCAN interface (typically vcan0) for testing the canopenreceiver's
// passive sniffing: a heartbeat, a TPDO with a sine-wave-ish speed signal,
// and an occasional EMCY frame. It is a development/test tool, not part of
// the receiver itself.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.einride.tech/can"
	"go.einride.tech/can/pkg/socketcan"
)

func main() {
	iface := flag.String("iface", "vcan0", "SocketCAN interface to publish on")
	nodeID := flag.Uint("node", 1, "CANopen node ID to simulate (1-127)")
	heartbeatInterval := flag.Duration("heartbeat-interval", time.Second, "heartbeat period")
	pdoInterval := flag.Duration("pdo-interval", 200*time.Millisecond, "TPDO1 publish period")
	emcyInterval := flag.Duration("emcy-interval", 0, "if > 0, periodically emit a benign EMCY frame")
	flag.Parse()

	if *nodeID < 1 || *nodeID > 127 {
		log.Fatalf("node id must be in range 1..127, got %d", *nodeID)
	}
	id := uint32(*nodeID)

	conn, err := socketcan.Dial("can", *iface)
	if err != nil {
		log.Fatalf("failed to dial %s: %v", *iface, err)
	}
	defer conn.Close()
	tx := socketcan.NewTransmitter(conn)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("canopen-publisher: iface=%s node=%d heartbeat=%s pdo=%s", *iface, id, *heartbeatInterval, *pdoInterval)

	send := func(f can.Frame) {
		if err := tx.TransmitFrame(ctx, f); err != nil && ctx.Err() == nil {
			log.Printf("send error (id=0x%X): %v", f.ID, err)
		}
	}

	// Bootup message (heartbeat COB-ID, state = 0x00).
	send(can.Frame{ID: 0x700 + id, Length: 1, Data: can.Data{0x00}})

	heartbeatTicker := time.NewTicker(*heartbeatInterval)
	defer heartbeatTicker.Stop()
	pdoTicker := time.NewTicker(*pdoInterval)
	defer pdoTicker.Stop()

	var emcyTicker *time.Ticker
	var emcyC <-chan time.Time
	if *emcyInterval > 0 {
		emcyTicker = time.NewTicker(*emcyInterval)
		defer emcyTicker.Stop()
		emcyC = emcyTicker.C
	}

	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("shutting down")
			return
		case <-heartbeatTicker.C:
			// Operational state (0x05).
			send(can.Frame{ID: 0x700 + id, Length: 1, Data: can.Data{0x05}})
		case <-pdoTicker.C:
			// TPDO1 (0x180+id): a signed int16 "speed" signal oscillating
			// with a sine wave, scaled by 0.1 rpm/unit on the receiver side.
			elapsed := time.Since(start).Seconds()
			speed := int16(1000 * math.Sin(elapsed))
			data := can.Data{}
			binary.LittleEndian.PutUint16(data[0:2], uint16(speed))
			send(can.Frame{ID: 0x180 + id, Length: 2, Data: data})
		case <-emcyC:
			// Benign "error reset" EMCY: code 0x0000, register 0x00.
			data := can.Data{}
			send(can.Frame{ID: 0x080 + id, Length: 8, Data: data})
		}
	}
}
