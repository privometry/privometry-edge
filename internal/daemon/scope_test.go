package daemon

import (
	"testing"

	"github.com/privometry/privometry-oss/internal/events"
)

func TestCwdScope(t *testing.T) {
	tests := []struct {
		cwd, home string
		want      events.ContextCwdScope
	}{
		{"/home/dev/notes", "/home/dev", events.ContextCwdScopeHome},
		{"/home/devops", "/home/dev", events.ContextCwdScopeOther},
		{"/etc/nginx", "/home/dev", events.ContextCwdScopeSystem},
		{`C:\Users\dev\notes`, `C:\Users\dev`, events.ContextCwdScopeHome},
		{`C:\Windows\System32`, `C:\Users\dev`, events.ContextCwdScopeSystem},
		{`C:\Program Files (x86)\Tool`, `C:\Users\dev`, events.ContextCwdScopeSystem},
		{`D:\`, `C:\Users\dev`, events.ContextCwdScopeSystem},
		{`D:\src\tool`, `C:\Users\dev`, events.ContextCwdScopeOther},
	}
	for _, tc := range tests {
		if got := cwdScope(&sessionInfo{Cwd: tc.cwd}, tc.home); got != tc.want {
			t.Errorf("cwdScope(%q) = %q, want %q", tc.cwd, got, tc.want)
		}
	}
}
