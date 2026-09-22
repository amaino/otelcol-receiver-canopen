package emit

import (
	"fmt"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// putAttribute writes a static attribute value to an OTel attribute map.
// The type switch only covers what the confmap YAML decoder can actually
// produce for a scalar config value: string, bool, int (platform word
// size), int64 (larger signed values, notably on 32-bit builds), uint64
// (positive values too large for int64), and float64. Anything else falls
// back to a string representation.
func putAttribute(attrs pcommon.Map, key string, value any) {
	switch v := value.(type) {
	case string:
		attrs.PutStr(key, v)
	case bool:
		attrs.PutBool(key, v)
	case int:
		attrs.PutInt(key, int64(v))
	case int64:
		attrs.PutInt(key, v)
	case uint64:
		attrs.PutInt(key, int64(v))
	case float64:
		attrs.PutDouble(key, v)
	default:
		attrs.PutStr(key, fmt.Sprint(v))
	}
}
