package content

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Flatten turns a JSON value into text for the detectors: strings as they
// are, object fields as "key: value" lines. Marshaling would escape
// characters (<, >, invisible Unicode) the detectors need to see.
func Flatten(v any) string {
	var b strings.Builder
	var walk func(key string, v any)
	walk = func(key string, v any) {
		prefix := ""
		if key != "" {
			prefix = key + ": "
		}
		switch x := v.(type) {
		case nil:
		case string:
			b.WriteString(prefix + x + "\n")
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(k, x[k])
			}
		case []any:
			for _, e := range x {
				walk(key, e)
			}
		case json.Number:
			b.WriteString(prefix + x.String() + "\n")
		case bool:
			b.WriteString(prefix + strconv.FormatBool(x) + "\n")
		case float64:
			b.WriteString(prefix + strconv.FormatFloat(x, 'f', -1, 64) + "\n")
		}
	}
	if s, ok := v.(string); ok {
		return s
	}
	walk("", v)
	return b.String()
}
