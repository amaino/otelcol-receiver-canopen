// Package sdoobserver passively reconstructs standard CANopen SDO transfers.
// It never sends frames or changes state on the CAN bus.
package sdoobserver

import "fmt"

// Direction identifies the direction of an SDO frame.
type Direction string

const (
	ClientToServer Direction = "client_to_server"
	ServerToClient Direction = "server_to_client"
	sdoFrameLength           = 8
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
	nodeID          uint8
	direction       Direction
	operation       string
	index           uint16
	subIndex        uint8
	uploadInitiated bool
	toggle          bool
	data            []byte
}

// Observer retains enough SDO state to reconstruct one standard transfer per
// configured channel. A channel key keeps concurrent transfers for multiple
// channels belonging to the same node independent.
type Observer struct {
	transfers map[uint32]*transfer
}

// New creates an empty passive observer.
func New() *Observer {
	return &Observer{transfers: make(map[uint32]*transfer)}
}

// Observe consumes an observed standard SDO frame. It returns an event only
// when a transfer completes or a server abort is observed.
func (o *Observer) Observe(nodeID uint8, direction Direction, frame []byte) (*Event, error) {
	return o.ObserveOnChannel(uint32(nodeID), nodeID, direction, frame)
}

// ObserveOnChannel consumes a frame belonging to a configured SDO channel.
// channelKey must uniquely identify the channel within the observer.
func (o *Observer) ObserveOnChannel(channelKey uint32, nodeID uint8, direction Direction, frame []byte) (*Event, error) {
	if len(frame) == 0 {
		return nil, nil
	}
	if len(frame) < sdoFrameLength {
		return nil, fmt.Errorf("truncated SDO frame for node %d: got %d bytes, need %d", nodeID, len(frame), sdoFrameLength)
	}
	command := frame[0]
	if direction == ServerToClient && command == 0x80 {
		index, subIndex := objectAddress(frame)
		abortCode := uint32(frame[4]) | uint32(frame[5])<<8 | uint32(frame[6])<<16 | uint32(frame[7])<<24
		delete(o.transfers, channelKey)
		return &Event{
			NodeID: nodeID, Direction: direction, Operation: "abort",
			Index: index, SubIndex: subIndex, AbortCode: &abortCode,
		}, nil
	}

	switch direction {
	case ClientToServer:
		return o.observeClient(channelKey, nodeID, command, frame)
	case ServerToClient:
		return o.observeServer(channelKey, nodeID, command, frame)
	default:
		return nil, fmt.Errorf("unknown SDO direction %q", direction)
	}
}

func (o *Observer) observeClient(channelKey uint32, nodeID uint8, command byte, frame []byte) (*Event, error) {
	if command == 0x40 {
		index, subIndex := objectAddress(frame)
		o.transfers[channelKey] = &transfer{nodeID: nodeID, direction: ServerToClient, operation: "upload", index: index, subIndex: subIndex}
		return nil, nil
	}
	if command&0xE0 == 0x20 {
		index, subIndex := objectAddress(frame)
		if command&0x02 != 0 {
			data := expeditedData(command, frame)
			return &Event{NodeID: nodeID, Direction: ClientToServer, Operation: "download", Index: index, SubIndex: subIndex, Data: data}, nil
		}
		o.transfers[channelKey] = &transfer{nodeID: nodeID, direction: ClientToServer, operation: "download", index: index, subIndex: subIndex}
		return nil, nil
	}
	if command&0xE0 != 0 {
		return nil, nil
	}
	return o.observeSegment(channelKey, nodeID, ClientToServer, command, frame)
}

func (o *Observer) observeServer(channelKey uint32, nodeID uint8, command byte, frame []byte) (*Event, error) {
	transfer := o.transfers[channelKey]
	if transfer == nil {
		return nil, nil
	}
	if transfer.operation == "upload" && command&0xE0 == 0x40 {
		index, subIndex := objectAddress(frame)
		if index != transfer.index || subIndex != transfer.subIndex {
			return nil, nil
		}
		if command&0x02 != 0 {
			data := expeditedData(command, frame)
			delete(o.transfers, channelKey)
			return complete(transfer, data), nil
		}
		transfer.uploadInitiated = true
		return nil, nil
	}
	if transfer.operation == "download" && command == 0x60 {
		return nil, nil
	}
	if command&0xE0 != 0 {
		return nil, nil
	}
	return o.observeSegment(channelKey, nodeID, ServerToClient, command, frame)
}

func (o *Observer) observeSegment(channelKey uint32, nodeID uint8, direction Direction, command byte, frame []byte) (*Event, error) {
	transfer := o.transfers[channelKey]
	if transfer == nil || transfer.direction != direction {
		return nil, nil
	}
	if transfer.operation == "upload" && !transfer.uploadInitiated {
		return nil, nil
	}
	toggle := command&0x10 != 0
	if toggle != transfer.toggle {
		delete(o.transfers, channelKey)
		return nil, fmt.Errorf("unexpected SDO toggle bit for node %d", nodeID)
	}
	unused := int((command >> 1) & 0x07)
	last := command&0x01 != 0
	if !last {
		unused = 0
	}
	transfer.data = append(transfer.data, frame[1:8-unused]...)
	transfer.toggle = !transfer.toggle
	if !last {
		return nil, nil
	}
	delete(o.transfers, channelKey)
	return complete(transfer, transfer.data), nil
}

func objectAddress(frame []byte) (uint16, uint8) {
	return uint16(frame[1]) | uint16(frame[2])<<8, frame[3]
}

func expeditedData(command byte, frame []byte) []byte {
	if command&0x01 == 0 {
		return append([]byte(nil), frame[4:8]...)
	}
	unused := int((command >> 2) & 0x03)
	return append([]byte(nil), frame[4:8-unused]...)
}

func complete(transfer *transfer, data []byte) *Event {
	return &Event{
		NodeID: transfer.nodeID, Direction: transfer.direction,
		Operation: transfer.operation, Index: transfer.index, SubIndex: transfer.subIndex,
		Data: append([]byte(nil), data...),
	}
}
