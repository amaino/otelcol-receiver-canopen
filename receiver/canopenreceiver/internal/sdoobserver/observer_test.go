package sdoobserver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObserver_ExpeditedUpload(t *testing.T) {
	o := New()
	event, err := o.Observe(1, ClientToServer, []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0})
	require.NoError(t, err)
	assert.Nil(t, event)

	event, err = o.Observe(1, ServerToClient, []byte{0x4B, 0x01, 0x20, 0x00, 0x34, 0x12, 0, 0})
	require.NoError(t, err)
	require.NotNil(t, event)
	assert.Equal(t, uint8(1), event.NodeID)
	assert.Equal(t, ServerToClient, event.Direction)
	assert.Equal(t, "upload", event.Operation)
	assert.Equal(t, uint16(0x2001), event.Index)
	assert.Equal(t, uint8(0), event.SubIndex)
	assert.Equal(t, []byte{0x34, 0x12}, event.Data)
}

func TestObserver_SegmentedUpload(t *testing.T) {
	o := New()
	_, err := o.Observe(1, ClientToServer, []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0})
	require.NoError(t, err)
	_, err = o.Observe(1, ServerToClient, []byte{0x41, 0x01, 0x20, 0x00, 0x0A, 0, 0, 0})
	require.NoError(t, err)

	_, err = o.Observe(1, ClientToServer, []byte{0x60, 0, 0, 0, 0, 0, 0, 0})
	require.NoError(t, err)
	event, err := o.Observe(1, ServerToClient, []byte{0x00, 'h', 'e', 'l', 'l', 'o', ' ', 'w'})
	require.NoError(t, err)
	assert.Nil(t, event)

	_, err = o.Observe(1, ClientToServer, []byte{0x70, 0, 0, 0, 0, 0, 0, 0})
	require.NoError(t, err)
	event, err = o.Observe(1, ServerToClient, []byte{0x17, 'o', 'r', 'l', 'd', 0, 0, 0})
	require.NoError(t, err)
	require.NotNil(t, event)
	assert.Equal(t, []byte("hello world"), event.Data)
}

func TestObserver_UploadIgnoresWrongObjectAndRecovers(t *testing.T) {
	for _, command := range []byte{0x43, 0x41} {
		for _, address := range []struct {
			name     string
			index    uint16
			subIndex uint8
		}{
			{name: "wrong index", index: 0xA000, subIndex: 0},
			{name: "wrong subindex", index: 0x2000, subIndex: 1},
		} {
			t.Run(fmt.Sprintf("%02X/%s", command, address.name), func(t *testing.T) {
				o := New()
				_, err := o.Observe(1, ClientToServer, []byte{0x40, 0, 0x20, 0, 0, 0, 0, 0})
				require.NoError(t, err)

				event, err := o.Observe(1, ServerToClient, []byte{
					command, byte(address.index), byte(address.index >> 8), address.subIndex,
					0xFF, 0xFF, 0xFF, 0xFF,
				})
				require.NoError(t, err)
				require.Nil(t, event)

				// Segments must not complete an upload whose initiation was rejected.
				event, err = o.Observe(1, ServerToClient, []byte{0x01, 1, 2, 3, 4, 5, 6, 7})
				require.NoError(t, err)
				require.Nil(t, event)

				event, err = o.Observe(1, ServerToClient, []byte{command, 0, 0x20, 0, 4, 0, 0, 0})
				require.NoError(t, err)
				if command == 0x41 {
					require.Nil(t, event)
					event, err = o.Observe(1, ServerToClient, []byte{0x07, 4, 0, 0, 0, 0, 0, 0})
					require.NoError(t, err)
				}
				require.NotNil(t, event)
				assert.Equal(t, uint16(0x2000), event.Index)
				assert.Equal(t, uint8(0), event.SubIndex)
				assert.Equal(t, []byte{4, 0, 0, 0}, event.Data)
			})
		}
	}
}

func TestObserver_TruncatedUploadResponsePreservesPendingRequest(t *testing.T) {
	for _, command := range []byte{0x43, 0x41} {
		for length := 1; length < 4; length++ {
			t.Run(fmt.Sprintf("%02X/length%d", command, length), func(t *testing.T) {
				o := New()
				_, err := o.Observe(1, ClientToServer, []byte{0x40, 0, 0x20, 0, 0, 0, 0, 0})
				require.NoError(t, err)
				frame := []byte{command, 0, 0x20, 0}
				event, err := o.Observe(1, ServerToClient, frame[:length])
				require.ErrorContains(t, err, "truncated SDO upload response")
				assert.Nil(t, event)

				event, err = o.Observe(1, ServerToClient, []byte{0x43, 0, 0x20, 0, 4, 0, 0, 0})
				require.NoError(t, err)
				require.NotNil(t, event)
				assert.Equal(t, []byte{4, 0, 0, 0}, event.Data)
			})
		}
	}
}

func TestObserver_SegmentedDownload(t *testing.T) {
	o := New()
	_, err := o.Observe(2, ClientToServer, []byte{0x21, 0x00, 0x20, 0x00, 0x08, 0, 0, 0})
	require.NoError(t, err)
	_, err = o.Observe(2, ServerToClient, []byte{0x60, 0x00, 0x20, 0x00, 0, 0, 0, 0})
	require.NoError(t, err)
	event, err := o.Observe(2, ClientToServer, []byte{0x00, 'a', 'b', 'c', 'd', 'e', 'f', 'g'})
	require.NoError(t, err)
	assert.Nil(t, event)
	event, err = o.Observe(2, ClientToServer, []byte{0x1D, 'h', 0, 0, 0, 0, 0, 0})
	require.NoError(t, err)
	require.NotNil(t, event)
	assert.Equal(t, ClientToServer, event.Direction)
	assert.Equal(t, "download", event.Operation)
	assert.Equal(t, []byte("abcdefgh"), event.Data)
}

func TestObserver_Abort(t *testing.T) {
	o := New()
	event, err := o.Observe(3, ServerToClient, []byte{0x80, 0x01, 0x20, 0x00, 0, 0, 0x02, 0x06})
	require.NoError(t, err)
	require.NotNil(t, event)
	require.NotNil(t, event.AbortCode)
	assert.Equal(t, uint32(0x06020000), *event.AbortCode)
}
