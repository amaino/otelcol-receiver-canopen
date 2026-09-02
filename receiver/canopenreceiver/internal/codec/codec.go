// Package codec implements CANopen data-type decoding: extracting typed values
// from little-endian PDO frame data at a
// configured bit/byte offset, and applying a linear scale/offset transform.
package codec

import (
	"encoding/binary"
	"fmt"
	"math"
)

// DataType identifies a CANopen basic data type used to interpret raw bytes.
type DataType string

// Supported CANopen basic data types (CiA 301).
const (
	Bool          DataType = "bool"
	Int8          DataType = "int8"
	Int16         DataType = "int16"
	Int32         DataType = "int32"
	Int64         DataType = "int64"
	Uint8         DataType = "uint8"
	Uint16        DataType = "uint16"
	Uint32        DataType = "uint32"
	Uint64        DataType = "uint64"
	Float32       DataType = "float32"
	Float64       DataType = "float64"
	Bytes         DataType = "bytes"
	VisibleString DataType = "visible_string"
)

// BitWidth returns the number of bits occupied by the given data type, or 0
// for variable-width types (Bytes, VisibleString).
func (t DataType) BitWidth() int {
	switch t {
	case Bool:
		return 1
	case Int8, Uint8:
		return 8
	case Int16, Uint16:
		return 16
	case Int32, Uint32, Float32:
		return 32
	case Int64, Uint64, Float64:
		return 64
	default:
		return 0
	}
}

// Valid reports whether t is one of the supported data types.
func (t DataType) Valid() bool {
	switch t {
	case Bool, Int8, Int16, Int32, Int64, Uint8, Uint16, Uint32, Uint64, Float32, Float64, Bytes, VisibleString:
		return true
	default:
		return false
	}
}

// Value is a decoded CANopen value, holding exactly one populated field
// depending on the source DataType.
type Value struct {
	Type   DataType
	Bool   bool
	Int    int64   // Int8, Int16, Int32, Int64
	Uint   uint64  // Uint8, Uint16, Uint32, Uint64
	Float  float64 // Float32, Float64, and any numeric type after scale/offset
	Bytes  []byte  // Bytes, VisibleString
	String string  // VisibleString
}

// Float returns the value as a float64 regardless of the source integer/float
// type, without applying scale/offset. Bool is 0/1. Bytes/VisibleString return 0.
func (v Value) AsFloat() float64 {
	switch v.Type {
	case Bool:
		if v.Bool {
			return 1
		}
		return 0
	case Int8, Int16, Int32, Int64:
		return float64(v.Int)
	case Uint8, Uint16, Uint32, Uint64:
		return float64(v.Uint)
	case Float32, Float64:
		return v.Float
	default:
		return 0
	}
}

// Decode extracts a value of the given type from data starting at bitOffset
// (0-based, little-endian bit numbering as used by CANopen PDO mapping: bit 0
// is the LSB of byte 0). For Bytes/VisibleString, bitOffset must be
// byte-aligned and byteLen bytes are copied.
func Decode(data []byte, dataType DataType, bitOffset int, byteLen int) (Value, error) {
	if !dataType.Valid() {
		return Value{}, fmt.Errorf("unsupported data type %q", dataType)
	}

	switch dataType {
	case Bytes, VisibleString:
		if bitOffset%8 != 0 {
			return Value{}, fmt.Errorf("byte-oriented type %q requires byte-aligned bit_offset, got %d", dataType, bitOffset)
		}
		start := bitOffset / 8
		if byteLen <= 0 {
			return Value{}, fmt.Errorf("byte_len must be > 0 for type %q", dataType)
		}
		if start < 0 || start+byteLen > len(data) {
			return Value{}, fmt.Errorf("byte range [%d:%d] out of bounds for payload of length %d", start, start+byteLen, len(data))
		}
		raw := make([]byte, byteLen)
		copy(raw, data[start:start+byteLen])
		if dataType == VisibleString {
			return Value{Type: dataType, Bytes: raw, String: string(raw)}, nil
		}
		return Value{Type: dataType, Bytes: raw}, nil
	}

	width := dataType.BitWidth()
	raw, err := extractBits(data, bitOffset, width)
	if err != nil {
		return Value{}, err
	}

	switch dataType {
	case Bool:
		return Value{Type: dataType, Bool: raw&1 != 0}, nil
	case Int8:
		return Value{Type: dataType, Int: int64(int8(raw))}, nil
	case Int16:
		return Value{Type: dataType, Int: int64(int16(raw))}, nil
	case Int32:
		return Value{Type: dataType, Int: int64(int32(raw))}, nil
	case Int64:
		return Value{Type: dataType, Int: int64(raw)}, nil
	case Uint8, Uint16, Uint32, Uint64:
		return Value{Type: dataType, Uint: raw}, nil
	case Float32:
		return Value{Type: dataType, Float: float64(math.Float32frombits(uint32(raw)))}, nil
	case Float64:
		return Value{Type: dataType, Float: math.Float64frombits(raw)}, nil
	default:
		return Value{}, fmt.Errorf("unsupported data type %q", dataType)
	}
}

// extractBits reads `width` bits (8, 16, 32, or 64) starting at bitOffset from
// data, using little-endian byte order and LSB-first bit numbering, returning
// the result right-aligned in a uint64.
func extractBits(data []byte, bitOffset, width int) (uint64, error) {
	if bitOffset < 0 {
		return 0, fmt.Errorf("bit_offset must be >= 0, got %d", bitOffset)
	}
	if width == 0 {
		return 0, fmt.Errorf("invalid zero-width type")
	}
	// Fast path: byte-aligned standard widths read directly to avoid bit-shift
	// edge cases and to match CANopen's little-endian encoding exactly.
	if bitOffset%8 == 0 {
		start := bitOffset / 8
		end := start + width/8
		if start < 0 || end > len(data) {
			return 0, fmt.Errorf("field [%d:%d] (bits %d..%d) out of bounds for payload of length %d bytes", start, end, bitOffset, bitOffset+width, len(data))
		}
		switch width {
		case 8:
			return uint64(data[start]), nil
		case 16:
			return uint64(binary.LittleEndian.Uint16(data[start:end])), nil
		case 32:
			return uint64(binary.LittleEndian.Uint32(data[start:end])), nil
		case 64:
			return binary.LittleEndian.Uint64(data[start:end]), nil
		}
	}

	// General bit-level path for sub-byte alignment (e.g. bit-packed PDO
	// signals sharing a byte). Reads width bits starting at bitOffset,
	// LSB-first across the byte stream.
	totalBits := len(data) * 8
	if bitOffset+width > totalBits {
		return 0, fmt.Errorf("field at bit %d width %d out of bounds for payload of %d bits", bitOffset, width, totalBits)
	}
	var result uint64
	for i := 0; i < width; i++ {
		bitPos := bitOffset + i
		byteIdx := bitPos / 8
		bitIdx := uint(bitPos % 8)
		bit := (data[byteIdx] >> bitIdx) & 1
		result |= uint64(bit) << uint(i)
	}
	return result, nil
}

// ApplyScale applies a linear transform (value*scale + offset) to a decoded
// numeric Value and returns the resulting float64. Bool/Bytes/VisibleString
// values are converted via AsFloat before scaling (Bool only; byte types
// return 0 and scale/offset should not be configured for them).
func ApplyScale(v Value, scale, offset float64) float64 {
	if scale == 0 {
		scale = 1
	}
	return v.AsFloat()*scale + offset
}
