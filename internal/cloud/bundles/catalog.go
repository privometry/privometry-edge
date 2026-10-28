package bundles

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/contract"
)

// CatalogItem is something the organization's catalog can approve or block:
// an agent, MCP server, skill, plugin or IDE extension. Fields the device
// does not know are empty.
type CatalogItem struct {
	Kind      string // agent, mcp_server, skill, plugin, ide_extension
	Name      string
	Version   string
	Transport string // stdio or http
	Package   string
	URL       string
	Command   string
}

// CatalogStatus classifies an item by the organization's catalog, as the
// privometry/mcp-allowlist rules expect: blocked when a blocked entry of its
// kind matches; approved when an approved entry matches its version too;
// unapproved when it is in the catalog but not approved (an approved entry
// lists other versions); unknown when it is not in the catalog at all
// (shadow AI); and empty when the catalog lists nothing of its kind, so no
// catalog rule applies. Expired entries do not count. The platform applies
// the same rules to inventory, except command globs, which only devices see.
func (c BundleCatalog) CatalogStatus(it CatalogItem, now time.Time) (contract.CatalogStatus, *BundleCatalogEntry) {
	var approved, listed *BundleCatalogEntry
	any := false
	for i := range c.Entries {
		e := &c.Entries[i]
		if string(e.Kind) != it.Kind || (e.ExpiresAt != nil && !now.Before(e.ExpiresAt.Time)) {
			continue
		}
		any = true
		if !e.matches(it) {
			continue
		}
		if e.Status == BundleCatalogEntryStatusBlocked {
			return contract.CatalogStatusBlocked, e
		}
		if approved == nil && (len(e.Versions) == 0 || it.Version == "" || slices.Contains(e.Versions, it.Version)) {
			approved = e
		} else if listed == nil {
			listed = e
		}
	}
	switch {
	case approved != nil:
		return contract.CatalogStatusApproved, approved
	case listed != nil:
		return contract.CatalogStatusUnapproved, listed
	case any:
		return contract.CatalogStatusUnknown, nil
	}
	return "", nil
}

func (e *BundleCatalogEntry) matches(it CatalogItem) bool {
	m := e.Match
	if m != nil && m.Transport != "" && string(m.Transport) != it.Transport {
		return false
	}
	if strings.EqualFold(e.Name, it.Name) {
		return true
	}
	if m == nil {
		return false
	}
	return glob(m.Package, it.Package) || glob(m.URL, it.URL) || glob(m.Command, it.Command)
}

// glob matches policy globs: * is any run of characters, everything else is literal.
func glob(pattern, s string) bool {
	if pattern == "" || s == "" {
		return false
	}
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$").MatchString(s)
}
