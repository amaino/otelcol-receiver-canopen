package sdoobserver

import (
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
