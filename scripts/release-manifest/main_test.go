package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactsFromChecksums(t *testing.T) {
	dist := t.TempDir()
	files := map[string]int{"privometry_1.2.0_darwin_arm64.tar.gz": 10, "privometry_1.2.0_windows_amd64.zip": 20, "privometry_1.1.0_linux_amd64.tar.gz": 5}
	for f, n := range files {
		os.WriteFile(filepath.Join(dist, f), make([]byte, n), 0o644)
	}
	sum := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte(sum+"  privometry_1.2.0_darwin_arm64.tar.gz\n"+sum+"  privometry_1.2.0_windows_amd64.zip\n"+
		sum+"  privometry_1.1.0_linux_amd64.tar.gz\n"+sum+"  privometry.cdx.json\n"), 0o644)
	arts, err := artifacts(dist, "1.2.0", "https://example.test/v1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 2 {
		t.Fatalf("artifacts %+v", arts)
	}
	if a := arts[0]; a.OS != "macos" || a.Arch != "arm64" || a.Size != 10 || a.Format != "tar.gz" || a.SHA256 != "sha256:"+sum ||
		a.URL != "https://example.test/v1.2.0/privometry_1.2.0_darwin_arm64.tar.gz" {
		t.Errorf("darwin artifact %+v", a)
	}
	if a := arts[1]; a.OS != "windows" || a.Format != "zip" || a.Size != 20 {
		t.Errorf("windows artifact %+v", a)
	}
	if _, err := artifacts(dist, "9.9.9", "https://example.test"); err == nil {
		t.Error("no archives for a version must be an error")
	}
}
