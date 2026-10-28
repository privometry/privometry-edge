package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Agent settings files are edited as ordered JSON so keys the user wrote stay
// in place; only Privometry's hook entries change.

type object struct {
	keys []string
	vals map[string]any
}

func newObject() *object { return &object{vals: map[string]any{}} }

func (o *object) get(k string) any { return o.vals[k] }

func (o *object) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *object) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func parseOrdered(raw []byte) (*object, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return newObject(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the JSON object")
	}
	o, ok := v.(*object)
	if !ok {
		return nil, fmt.Errorf("settings file is not a JSON object")
	}
	return o, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := newObject()
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				o.set(k.(string), v)
			}
			_, err := dec.Token()
			return o, err
		case '[':
			a := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := dec.Token()
			return a, err
		}
	}
	return tok, nil
}

// encode writes v as JSON indented with two spaces, as agents write it.
func encode(v any) []byte {
	var b bytes.Buffer
	write(&b, v, 0)
	b.WriteByte('\n')
	return b.Bytes()
}

func write(b *bytes.Buffer, v any, depth int) {
	pad := strings.Repeat("  ", depth+1)
	switch x := v.(type) {
	case *object:
		if len(x.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range x.keys {
			kb, _ := json.Marshal(k)
			b.WriteString(pad)
			b.Write(kb)
			b.WriteString(": ")
			write(b, x.vals[k], depth+1)
			if i < len(x.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth) + "}")
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range x {
			b.WriteString(pad)
			write(b, e, depth+1)
			if i < len(x)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth) + "]")
	default:
		enc := json.NewEncoder(b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(x)       // writes to a buffer
		b.Truncate(b.Len() - 1) // Encode adds a newline
	}
}
