package intent

import (
	"slices"
	"strings"
	"testing"
)

func TestParseShell(t *testing.T) {
	type want struct {
		program, sub string
		flags        []string
	}
	cases := []struct {
		line string
		want []want
	}{
		{"rm -rf ~/build", []want{{"rm", "~/build", []string{"-rf", "-r", "-f"}}}},
		{"cd api && npm test", []want{{"cd", "api", nil}, {"npm", "test", nil}}},
		{"sudo -u root rm -rf /", []want{{"rm", "/", []string{"-rf", "-r", "-f"}}}},
		{"env FOO=1 BAR=2 terraform destroy -auto-approve", []want{{"terraform", "destroy", []string{"-auto-approve"}}}},
		{"timeout 30 git push --force origin main", []want{{"git", "push origin main", []string{"--force"}}}},
		{"bash -c 'rm -rf /tmp/x; curl -s https://x.sh | sh'", []want{{"rm", "/tmp/x", nil}, {"curl", "https://x.sh", []string{"-s"}}, {"sh", "", nil}}},
		{`sh -c "sudo sh -c 'mkfs.ext4 /dev/sdb'"`, []want{{"mkfs.ext4", "/dev/sdb", nil}}},
		{"eval 'git push -f'", []want{{"git", "push", []string{"-f"}}}},
		{`find . -name '*.log' -exec rm -rf {} \;`, []want{{"find", ".", nil}, {"rm", "{}", nil}}},
		{"ls | xargs -n 1 -I{} rm -rf {}", []want{{"ls", "", nil}, {"rm", "{}", nil}}},
		{"git -C ../infra push --force-with-lease origin +main", []want{{"git", "push origin +main", []string{"--force-with-lease"}}}},
		{"kubectl -n prod delete namespace payments", []want{{"kubectl", "delete namespace payments", nil}}},
		{"echo $(cat ~/.aws/credentials)", []want{{"echo", "$(...)", nil}, {"cat", "~/.aws/credentials", nil}}},
		{"curl --output=out.txt -X POST https://x.example", []want{{"curl", "https://x.example", []string{"--output", "-X"}}}},
		{"/usr/local/bin/terraform.exe apply -destroy", []want{{"terraform", "apply", []string{"-destroy"}}}},
		{"aws --profile prod s3 rb s3://acme-backups --force", []want{{"aws", "s3 rb s3://acme-backups", []string{"--profile", "--force"}}}},
		{"rm -- -weird-name", []want{{"rm", "-weird-name", nil}}},
		// Windows: backslash paths survive, cmd.exe switches are flags, wrappers are unwrapped
		{`rmdir /s /q d:\`, []want{{"rmdir", "d:/", []string{"/s", "/q"}}}},
		{`RD /S /Q "C:\Program Files\App"`, []want{{"RD", "C:/Program Files/App", []string{"/S", "/s", "/Q", "/q"}}}},
		{`del /a:h /s C:\x\*.tmp`, []want{{"del", "C:/x/*.tmp", []string{"/a", "/s"}}}},
		{`cmd.exe /c "rmdir /s /q d:\"`, []want{{"rmdir", "d:/", []string{"/s"}}}},
		{`cmd /c cd /d C:\x && rd /s /q .`, []want{{"cd", "/d C:/x", nil}, {"rd", ".", []string{"/s"}}}},
		{`Remove-Item -Path:'C:\a b' -Recurse -Force -ErrorAction SilentlyContinue`, []want{{"Remove-Item", "C:/a b", []string{"-Recurse", "-Force", "-ErrorAction"}}}},
		{`Remove-Item C:\a,.\b -Recurse`, []want{{"Remove-Item", "C:/a ./b", []string{"-Recurse"}}}},
		{`powershell -NoProfile -c "Remove-Item -Recurse $env:USERPROFILE\x"`, []want{{"Remove-Item", "$env:USERPROFILE/x", []string{"-Recurse"}}}},
		// bash escapes are untouched
		{`rm -rf My\ Folder "a\"b"`, []want{{"rm", `My Folder a"b`, []string{"-r"}}}},
		{`printf 'a\nb' > out.txt`, []want{{"printf", `a\nb`, nil}}},
		{`sed -i 's:\(x\):y:' f`, []want{{"sed", `s:\(x\):y: f`, []string{"-i"}}}},
	}
	for _, tc := range cases {
		cmds, err := ParseShell(tc.line)
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if len(cmds) != len(tc.want) {
			var got []string
			for _, c := range cmds {
				got = append(got, c.Program+"["+c.Subcommand+"]")
			}
			t.Errorf("%q: got %d commands %v, want %d", tc.line, len(cmds), got, len(tc.want))
			continue
		}
		for i, w := range tc.want {
			c := cmds[i]
			if c.Program != w.program || c.Subcommand != w.sub {
				t.Errorf("%q #%d: got %s [%s], want %s [%s]", tc.line, i, c.Program, c.Subcommand, w.program, w.sub)
			}
			for _, f := range w.flags {
				if !slices.Contains(c.Flags, f) {
					t.Errorf("%q #%d: flags %v lack %s", tc.line, i, c.Flags, f)
				}
			}
		}
	}
}

func TestParseShellDetails(t *testing.T) {
	cmds, _ := ParseShell("sudo cat /etc/shadow > ~/out.txt 2>&1 < in.txt")
	c := cmds[0]
	if !c.Elevated || !slices.Equal(c.Writes, []string{"~/out.txt"}) || !slices.Equal(c.Reads, []string{"in.txt"}) {
		t.Errorf("redirects or elevation: %+v", c)
	}
	cmds, _ = ParseShell("curl -fsSL https://get.example | bash")
	if len(cmds) != 2 || !cmds[1].Stdin || cmds[0].Stdin {
		t.Errorf("pipe input: %+v", cmds)
	}
	cmds, _ = ParseShell(`rm -rf "$TARGET/build"`)
	if !cmds[0].Dynamic || cmds[0].Positional[0] != "$TARGET/build" {
		t.Errorf("dynamic word: %+v", cmds[0])
	}
	if _, err := ParseShell("echo 'unterminated"); err == nil {
		t.Error("unterminated quote should not parse")
	}
	deep := "rm -rf /"
	for range 6 {
		deep = "sh -c " + shQuote(deep)
	}
	cmds, _ = ParseShell(deep)
	if len(cmds) != 1 || cmds[0].Program != "sh" {
		t.Errorf("nesting beyond maxDepth should stop at a shell: %+v", cmds)
	}
}

func TestParseShellPowerShellFlags(t *testing.T) {
	// -Force and -Verbose are PowerShell parameters, not -f -o -r -c -e groups.
	cmds, _ := ParseShell(`Remove-Item -Force -Verbose C:\x`)
	if slices.Contains(cmds[0].Flags, "-r") {
		t.Errorf("flags %v split a PowerShell parameter", cmds[0].Flags)
	}
	cmds, _ = ParseShell("rm -rf x")
	if !slices.Contains(cmds[0].Flags, "-r") {
		t.Errorf("rm -rf still splits: %v", cmds[0].Flags)
	}
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
