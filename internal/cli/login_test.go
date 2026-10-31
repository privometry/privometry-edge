package cli

import (
	"bytes"
	"strings"
	"testing"
)

// Without a connector, login explains how to get the connected build.
func TestLoginNeedsTheConnectedBuild(t *testing.T) {
	for _, cmd := range connectedOnly {
		var out, errOut bytes.Buffer
		if code := run([]string{cmd}, &out, &errOut); code != 2 {
			t.Errorf("%s: exit %d, want 2", cmd, code)
		}
		if !strings.Contains(errOut.String(), "connected build") || !strings.Contains(errOut.String(), connectedURL) {
			t.Errorf("%s: %q", cmd, errOut.String())
		}
	}
	var out bytes.Buffer
	run([]string{"help"}, &out, &out)
	if !strings.Contains(out.String(), "login ") {
		t.Errorf("usage does not list login:\n%s", out.String())
	}
}
