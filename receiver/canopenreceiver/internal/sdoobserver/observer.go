// Package sdoobserver passively reconstructs standard CANopen SDO transfers.
// It never sends frames or changes state on the CAN bus.
package sdoobserver

import "fmt"

// Direction identifies the direction of an SDO frame.
type Direction string

const (
	ClientToServer Direction = "client_to_server"
	ServerToClient Direction = "server_to_client"
)

// Event is a completed expedited or segmented SDO transfer, or an SDO abort.
type Event struct {
	NodeID    uint8
	Direction Direction
	Operation string
	Index     uint16
	SubIndex  uint8
	Data      []byte
	AbortCode *uint32
}

type transfer struct {
	nodeID    uint8
	direction Direction
	operation string
	index     uint16
	subIndex  uint8
	toggle    bool
	data      []byte
}

// Observer retains enough SDO state to reconstruct one standard transfer per
// node. Standard SDO channels allow only one transfer per node at a time.
type Observer struct {
	transfers map[uint8]*transfer
}

// New creates an empty passive observer.
func New() *Observer {
	return &Observer{transfers: make(map[uint8]*transfer)}
}

// Observe consumes an observed standard SDO frame. It returns an event only
// when a transfer completes or a server abort is observed.
func (o *Observer) Observe(nodeID uint8, direction Direction, frame []byte) (*Event, error) {
	if len(frame) == 0 {
		return nil, nil
	}
	command := frame[0]
	if direction == ServerToClient && command == 0x80 {
		if len(frame) < 8 {
			return nil, fmt.Errorf("truncated SDO abort for node %d", nodeID)
		}
		index, subIndex := objectAddress(frame)
		abortCode := uint32(frame[4]) | uint32(frame[5])<<8 | uint32(frame[6])<<16 | uint32(frame[7])<<24
		delete(o.transfers, nodeID)
		return &Event{
			NodeID: nodeID, Direction: direction, Operation: "abort",
			Index: index, SubIndex: subIndex, AbortCode: &abortCode,
		}, nil
	}

	switch direction {
	case ClientToServer:
		return o.observeClient(nodeID, command, frame)
	case ServerToClient:
		return o.observeServer(nodeID, command, frame)
	default:
		return nil, fmt.Errorf("unknown SDO direction %q", direction)
	}
}

func (o *Observer) observeClient(nodeID uint8, command byte, frame []byte) (*Event, error) {
	if command == 0x40 {
		if len(frame) < 4 {
			return nil, fmt.Errorf("truncated SDO upload request for node %d", nodeID)
		}
		index, subIndex := objectAddress(frame)
		o.transfers[nodeID] = &transfer{nodeID: nodeID, direction: ServerToClient, operation: "upload", index: index, subIndex: subIndex}
		return nil, nil
	}
	if command&0xE0 == 0x20 {
		if len(frame) < 4 {
			return nil, fmt.Errorf("truncated SDO download request for node %d", nodeID)
		}
		index, subIndex := objectAddress(frame)
		if command&0x02 != 0 {
			data, err := expeditedData(command, frame)
			if err != nil {
				return nil, err
			}
			return &Event{NodeID: nodeID, Direction: ClientToServer, Operation: "download", Index: index, SubIndex: subIndex, Data: data}, nil
		}
		o.transfers[nodeID] = &transfer{nodeID: nodeID, direction: ClientToServer, operation: "download", index: index, subIndex: subIndex}
		return nil, nil
	}
	if command&0xE0 != 0 {
		return nil, nil
	}
	return o.observeSegment(nodeID, ClientToServer, command, frame)
}

func (o *Observer) observeServer(nodeID uint8, command byte, frame []byte) (*Event, error) {
	transfer := o.transfers[nodeID]
	if transfer == nil {
		return nil, nil
	}
	if transfer.operation == "upload" && command&0xE0 == 0x40 {
		if command&0x02 != 0 {
			data, err := expeditedData(command, frame)
			if err != nil {
				return nil, err
			}
			delete(o.transfers, nodeID)
			return complete(transfer, data), nil
		}
		return nil, nil
	}
	if transfer.operation == "download" && command == 0x60 {
		return nil, nil
	}
	if command&0xE0 != 0 {
		return nil, nil
	}
	return o.observeSegment(nodeID, ServerToClient, command, frame)
}

func (o *Observer) observeSegment(nodeID uint8, direction Direction, command byte, frame []byte) (*Event, error) {
	transfer := o.transfers[nodeID]
	if transfer == nil || transfer.direction != direction {
		return nil, nil
	}
	if len(frame) < 1 {
		return nil, fmt.Errorf("truncated SDO segment for node %d", nodeID)
	}
	toggle := command&0x10 != 0
	if toggle != transfer.toggle {
		delete(o.transfers, nodeID)
		return nil, fmt.Errorf("unexpected SDO toggle bit for node %d", nodeID)
	}
	unused := int((command >> 1) & 0x07)
	last := command&0x01 != 0
	if !last {
		unused = 0
	}
	if unused > 7 || len(frame) < 8 {
		delete(o.transfers, nodeID)
		return nil, fmt.Errorf("truncated SDO segment for node %d", nodeID)
	}
	transfer.data = append(transfer.data, frame[1:8-unused]...)
	transfer.toggle = !transfer.toggle
	if !last {
		return nil, nil
	}
	delete(o.transfers, nodeID)
	return complete(transfer, transfer.data), nil
}

func objectAddress(frame []byte) (uint16, uint8) {
	return uint16(frame[1]) | uint16(frame[2])<<8, frame[3]
}

func expeditedData(command byte, frame []byte) ([]byte, error) {
	if len(frame) < 8 {
		return nil, fmt.Errorf("truncated expedited SDO transfer")
	}
	if command&0x01 == 0 {
		return append([]byte(nil), frame[4:8]...), nil
	}
	unused := int((command >> 2) & 0x03)
	return append([]byte(nil), frame[4:8-unused]...), nil
}

func complete(transfer *transfer, data []byte) *Event {
	return &Event{
		NodeID: transfer.nodeID, Direction: transfer.direction,
		Operation: transfer.operation, Index: transfer.index, SubIndex: transfer.subIndex,
		Data: append([]byte(nil), data...),
	}
}
