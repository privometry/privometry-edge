package content_test

import (
	"testing"
	"time"

	"github.com/privometry/privometry-edge/detectorpacks"
	"github.com/privometry/privometry-edge/internal/content"
)

func TestAllowlist(t *testing.T) {
	packs, err := content.Load(detectorpacks.FS)
	if err != nil {
		t.Fatal(err)
	}
	e := content.New(packs, content.Options{})
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	token := "gh" + "p_KtHF4vUCsMehGAkWvj7FAc9QeWJKY40uvSwM"
	text := `token = "` + token + `"`
	fs := e.Scan(content.SourceFileWrite, text)
	if len(fs) != 1 || fs[0].DetectorID != "privometry/credentials:github-token" {
		t.Fatalf("findings %+v", fs)
	}
	f := fs[0]

	cases := []struct {
		name  string
		entry content.AllowEntry
		path  string
		want  bool
	}{
		{"path glob", content.AllowEntry{Detectors: []string{"privometry/credentials:github-token"}, Paths: []string{"test/*"}}, "test/fixtures/a.ts", true},
		{"pack wildcard", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Paths: []string{"test/*.ts"}}, "test/fixtures/a.ts", true},
		{"other path", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Paths: []string{"test/*"}}, "src/a.ts", false},
		{"no path for commands", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Paths: []string{"*"}}, "", false},
		{"other detector", content.AllowEntry{Detectors: []string{"privometry/credentials:jwt"}, Paths: []string{"*"}}, "a.ts", false},
		{"other pack", content.AllowEntry{Detectors: []string{"privometry/injection:*"}, Paths: []string{"*"}}, "a.ts", false},
		{"value", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Values: []string{token}}, "", true},
		{"other value", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Values: []string{token + "x"}}, "", false},
		{"path and value both needed", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Paths: []string{"docs/*"}, Values: []string{token}}, "src/a.ts", false},
		{"expired", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Values: []string{token}, Expires: now}, "", false},
		{"not yet expired", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}, Values: []string{token}, Expires: now.Add(time.Hour)}, "", true},
		{"no paths or values is dropped", content.AllowEntry{Detectors: []string{"privometry/credentials:*"}}, "a.ts", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := content.NewAllowlist([]content.AllowEntry{c.entry})
			if got := a.Allowed(f, text, c.path, now); got != c.want {
				t.Errorf("Allowed = %v, want %v", got, c.want)
			}
			kept, dropped := a.Filter(fs, text, c.path, now)
			if c.want != (dropped == 1 && len(kept) == 0) {
				t.Errorf("Filter kept %d, dropped %d", len(kept), dropped)
			}
		})
	}
	var none *content.Allowlist
	if none.Allowed(f, text, "a.ts", now) {
		t.Error("a nil allowlist allowed a finding")
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pattern, s string
		want       bool
	}{
		{"test/*", "test/a/b.ts", true},
		{"*.md", "docs/a.md", true},
		{"docs/*/README.md", "docs/x/y/README.md", true},
		{"docs/*/README.md", "docs/README.md", false},
		{"~/.claude/*", "~/.claude/skills/x/SKILL.md", true},
		{"a", "a", true},
		{"a", "ab", false},
		{"*a*a*", "aa", true},
		{"*a*a*", "a", false},
	} {
		if got := content.Glob(c.pattern, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v", c.pattern, c.s, got)
		}
	}
}
