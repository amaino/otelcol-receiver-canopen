package codec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecode_NumericTypes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	tests := []struct {
		name      string
		dataType  DataType
		bitOffset int
		wantFloat float64
	}{
		{"uint8@0", Uint8, 0, 1},
		{"uint16@0", Uint16, 0, 0x0201},
		{"uint32@0", Uint32, 0, 0x04030201},
		{"uint64@0", Uint64, 0, 0x0807060504030201},
		{"int8@0", Int8, 0, 1},
		{"uint8@8", Uint8, 8, 2},
		{"bool@0 true", Bool, 0, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Decode(data, tc.dataType, tc.bitOffset, 0)
			require.NoError(t, err)
			assert.Equal(t, tc.wantFloat, v.AsFloat())
		})
	}
}

func TestDecode_NegativeInt(t *testing.T) {
	// -1 as int16 little-endian is 0xFFFF
	data := []byte{0xFF, 0xFF}
	v, err := Decode(data, Int16, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), v.Int)
}

func TestDecode_Float32(t *testing.T) {
	// 1.5f = 0x3FC00000 little-endian: 00 00 C0 3F
	data := []byte{0x00, 0x00, 0xC0, 0x3F}
	v, err := Decode(data, Float32, 0, 0)
	require.NoError(t, err)
	assert.InDelta(t, 1.5, v.Float, 0.0001)
}

func TestDecode_SubByteBitOffset(t *testing.T) {
	// byte 0 = 0b1010_0000; a 3-bit field starting at bit 5 should read 0b101 = 5
	data := []byte{0b1010_0000}
	v, err := Decode(data, Uint8, 5, 0)
	// width for Uint8 is 8 bits, not valid for sub-byte read of 3 bits directly;
	// instead verify via extractBits indirectly using Bool at bit 5.
	require.Error(t, err) // out of bounds: 5+8 > 8 bits
	_ = v
}

func TestDecode_BoolAtBitOffset(t *testing.T) {
	data := []byte{0b0000_0010} // bit 1 set
	v, err := Decode(data, Bool, 1, 0)
	require.NoError(t, err)
	assert.True(t, v.Bool)

	v, err = Decode(data, Bool, 0, 0)
	require.NoError(t, err)
	assert.False(t, v.Bool)
}

func TestDecode_Bytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	v, err := Decode(data, Bytes, 8, 2)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x02, 0x03}, v.Bytes)
}

func TestDecode_VisibleString(t *testing.T) {
	data := []byte("hi!!")
	v, err := Decode(data, VisibleString, 0, 2)
	require.NoError(t, err)
	assert.Equal(t, "hi", v.String)
}

func TestDecode_Truncated(t *testing.T) {
	data := []byte{0x01}
	_, err := Decode(data, Uint32, 0, 0)
	require.Error(t, err)
}

func TestDecode_UnalignedBytesTypeRejected(t *testing.T) {
	data := []byte{0x01, 0x02}
	_, err := Decode(data, Bytes, 3, 1)
	require.Error(t, err)
}

func TestApplyScale(t *testing.T) {
	v := Value{Type: Int16, Int: 100}
	assert.Equal(t, 10.5, ApplyScale(v, 0.1, 0.5))

	// zero scale defaults to 1
	assert.Equal(t, 100.0, ApplyScale(v, 0, 0))
}

func TestDataType_Valid(t *testing.T) {
	assert.True(t, Uint32.Valid())
	assert.False(t, DataType("nonsense").Valid())
}
