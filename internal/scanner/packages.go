package scanner

import "strings"

// PackageName drops a version from a package reference: @scope/pkg@1.2.3 is
// @scope/pkg, mcp-server-fetch==0.6 is mcp-server-fetch.
func PackageName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.Index(p, "=="); i > 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i > 0 {
		p = p[:i]
	}
	if len(p) > 256 {
		p = p[:256]
	}
	return p
}
