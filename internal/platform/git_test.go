package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeRemote(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:Acme/API.git":                        "github.com/acme/api",
		"https://github.com/acme/api":                        "github.com/acme/api",
		"https://x-access-token:abc@github.com/acme/api.git": "github.com/acme/api",
		"ssh://git@gitlab.example.com:2222/team/svc.git":     "gitlab.example.com/team/svc",
		"https://dev.azure.com/org/proj/_git/repo/":          "dev.azure.com/org/proj/_git/repo",
	} {
		if got := NormalizeRemote(in); got != want {
			t.Errorf("NormalizeRemote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitRootAndRemote(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = git@github.com:other/x.git\n[remote \"origin\"]\n\turl = git@github.com:acme/api.git\n"
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := GitRoot(sub); got != root {
		t.Errorf("GitRoot = %q, want %q", got, root)
	}
	if got := GitRemote(root); got != "github.com/acme/api" {
		t.Errorf("GitRemote = %q", got)
	}
	if got := GitRoot(t.TempDir()); got != "" {
		t.Errorf("GitRoot outside a repo = %q", got)
	}
}
