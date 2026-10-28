package redact_test

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-oss/internal/redact"
)

// TestVectors runs specs/conformance/redaction/vectors.yaml. Inputs may hold
// {{}} so sample tokens are not contiguous in the repo; it is removed here.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("../../specs/conformance/redaction/vectors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Schema  string `yaml:"schema"`
		Context struct {
			Home     string `yaml:"home"`
			RepoRoot string `yaml:"repo_root"`
		} `yaml:"context"`
		HashKey string `yaml:"hash_key"`
		Tests   []struct {
			Name   string `yaml:"name"`
			Level  string `yaml:"level"`
			Input  string `yaml:"input"`
			Expect string `yaml:"expect"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Schema != "privometry.redactiontest/v1" || len(file.Tests) == 0 {
		t.Fatalf("unexpected vectors file: %q with %d tests", file.Schema, len(file.Tests))
	}
	key, err := base64.StdEncoding.DecodeString(file.HashKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := redact.Context{Home: file.Context.Home, RepoRoot: file.Context.RepoRoot}
	for _, tc := range file.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			in := strings.ReplaceAll(tc.Input, "{{}}", "")
			var got string
			switch tc.Level {
			case "redacted":
				got = redact.Redact(in, ctx)
			case "hashed":
				got = redact.Hash(key, in)
			default:
				t.Fatalf("unknown level %q", tc.Level)
			}
			if got != tc.Expect {
				t.Errorf("\n input %q\n   got %q\n  want %q", in, got, tc.Expect)
			}
		})
	}
}

// TestIdempotent: redacting already-redacted text changes nothing, so a
// second pass (for example in the cloud) is safe.
func TestIdempotent(t *testing.T) {
	ctx := redact.Context{Home: "/home/dev", RepoRoot: "/home/dev/work/api"}
	for _, s := range []string{
		"AWS_ACCESS_KEY_ID=<aws_key> aws s3 ls",
		"curl 'https://x.example/f?X-Amz-Signature=<redacted>'",
		"rm -rf ~/<redacted_path> <repo>/build",
		"psql postgres://<credentials>@db:5432/app --password <secret>",
	} {
		if got := redact.Redact(s, ctx); got != s {
			t.Errorf("not idempotent:\n in  %q\n out %q", s, got)
		}
	}
}

func TestSecretsKeepsPaths(t *testing.T) {
	in := "open /Users/dev/src/app/main.go with AWS_SECRET_ACCESS_KEY=" + "abcd1234abcd1234abcd1234abcd1234abcd1234" + " for /Users/other/x"
	got := redact.Secrets(in, "/Users/dev")
	if !strings.Contains(got, "~/src/app/main.go") || !strings.Contains(got, "/Users/<user>/x") || strings.Contains(got, "abcd1234") {
		t.Errorf("Secrets: %q", got)
	}
}

func TestWindowsPaths(t *testing.T) {
	ctx := redact.Context{Home: `C:\Users\dev`, RepoRoot: `C:\Users\dev\work\api`}
	for in, want := range map[string]string{
		`type C:\Users\dev\work\api\src\main.go`:     `type <repo>\src\main.go`,
		`del C:\Users\dev\Downloads\old.zip`:         `del ~/<redacted_path>`,
		`dir C:\Users\dev`:                           `dir ~`,
		`type C:\Users\sam\.ssh\id_ed25519`:          `type C:\Users\<user>\.ssh\id_ed25519`,
		`type c:\users\sam\notes.txt`:                `type c:\users\<user>\notes.txt`,
		`dir C:\Users\devops\notes`:                  `dir C:\Users\<user>\notes`,
		`type C:\Windows\System32\drivers\etc\hosts`: `type C:\Windows\System32\drivers\etc\hosts`,
	} {
		if got := redact.Redact(in, ctx); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	if got := redact.Secrets(`log at C:\Users\dev\AppData\Local\Privometry and C:\Users\sam\x`, `C:\Users\dev`); got != `log at ~\AppData\Local\Privometry and C:\Users\<user>\x` {
		t.Errorf("Secrets: %q", got)
	}
}
