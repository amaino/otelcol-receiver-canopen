package emit

import (
	"fmt"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func putAttribute(attrs pcommon.Map, key string, value any) {
	switch v := value.(type) {
	case string:
		attrs.PutStr(key, v)
	case bool:
		attrs.PutBool(key, v)
	case int:
		attrs.PutInt(key, int64(v))
	case int8:
		attrs.PutInt(key, int64(v))
	case int16:
		attrs.PutInt(key, int64(v))
	case int32:
		attrs.PutInt(key, int64(v))
	case int64:
		attrs.PutInt(key, v)
	case uint:
		attrs.PutInt(key, int64(v))
	case uint8:
		attrs.PutInt(key, int64(v))
	case uint16:
		attrs.PutInt(key, int64(v))
	case uint32:
		attrs.PutInt(key, int64(v))
	case uint64:
		attrs.PutInt(key, int64(v))
	case float32:
		attrs.PutDouble(key, float64(v))
	case float64:
		attrs.PutDouble(key, v)
	default:
		attrs.PutStr(key, fmt.Sprint(v))
	}
}
