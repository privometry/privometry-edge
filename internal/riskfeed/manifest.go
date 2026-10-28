package riskfeed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ManifestHash is a server's tool_manifest_hash (riskfeed/v1): what its tools
// are, as the feed and the edge both compute it. Each tool is reduced to its
// name, description and inputSchema, written as canonical JSON (object keys
// sorted, no insignificant whitespace, <, > and & not escaped), the tools are
// sorted by name and joined with newlines, and the result is hashed with
// SHA-256. specs/conformance/riskfeed/manifest-hashes.json holds vectors the
// platform's implementation must reproduce.
func ManifestHash(tools []any) string {
	type tool struct {
		name string
		line []byte
	}
	var all []tool
	for _, t := range tools {
		m, _ := t.(map[string]any)
		name, _ := m["name"].(string)
		reduced := map[string]any{"name": name}
		if d, ok := m["description"]; ok {
			reduced["description"] = d
		}
		if s, ok := m["inputSchema"]; ok {
			reduced["inputSchema"] = s
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(reduced)
		all = append(all, tool{name, bytes.TrimSuffix(buf.Bytes(), []byte("\n"))})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].name < all[j].name })
	h := sha256.New()
	for i, t := range all {
		if i > 0 {
			h.Write([]byte("\n"))
		}
		h.Write(t.line)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
