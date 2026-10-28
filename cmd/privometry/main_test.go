package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../../test/fixtures/scan/root/home/dev/work/api")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanRepoOnly(t *testing.T) {
	repo := fixtureRepo(t)
	cases := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"table", []string{"--no-machine", "--repo", repo}, 0, "WORTH FIXING (3)"},
		{"json", []string{"--no-machine", "--repo", repo, "--format", "json"}, 0, `"schema": "privometry.scan/v0"`},
		{"sarif", []string{"--no-machine", "--repo", repo, "--format", "sarif"}, 0, `"version": "2.1.0"`},
		{"fail on medium", []string{"--no-machine", "--repo", repo, "--fail-on", "medium"}, 1, "WORTH FIXING"},
		{"pass at critical", []string{"--no-machine", "--repo", repo, "--fail-on", "critical"}, 0, ""},
		{"bad format", []string{"--no-machine", "--repo", repo, "--format", "xml"}, 2, ""},
		{"bad fail-on", []string{"--no-machine", "--repo", repo, "--fail-on", "severe"}, 2, ""},
		{"nothing to scan", []string{"--no-machine", "--no-repo"}, 2, ""},
		{"missing repo", []string{"--no-machine", "--repo", filepath.Join(repo, "nope")}, 2, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(append([]string{"scan"}, tc.args...), &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.out) {
				t.Errorf("output lacks %q:\n%s", tc.out, stdout.String())
			}
		})
	}
}

func TestScanOutputFile(t *testing.T) {
	repo := fixtureRepo(t)
	out := filepath.Join(t.TempDir(), "privometry.sarif")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--no-machine", "--repo", repo, "--format", "sarif", "--output", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) || stdout.Len() != 0 {
		t.Errorf("SARIF file valid=%v, stdout %q", json.Valid(raw), stdout.String())
	}
}
