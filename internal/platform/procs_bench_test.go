package platform

import "testing"

// BenchmarkProcesses measures the listing the daemon takes every minute for
// silent agents (target: under 50 ms on a busy machine).
func BenchmarkProcesses(b *testing.B) {
	for b.Loop() {
		if _, err := Processes(); err != nil {
			b.Skip(err)
		}
	}
}

// BenchmarkProcessInfo measures one step of the walk from a hook call up to
// its agent.
func BenchmarkProcessInfo(b *testing.B) {
	for b.Loop() {
		if _, err := ProcessInfo(1); err != nil {
			b.Skip(err)
		}
	}
}
