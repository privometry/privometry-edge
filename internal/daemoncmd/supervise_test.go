package daemoncmd

import (
	"slices"
	"testing"
	"time"
)

func TestWithoutSupervise(t *testing.T) {
	got := withoutSupervise([]string{"-supervise", "-log", `C:\p\privometryd.log`, "--supervise=true", "-home", "D:\\home"})
	if want := []string{"-log", `C:\p\privometryd.log`, "-home", "D:\\home"}; !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
}

func TestRestartDelay(t *testing.T) {
	var d time.Duration
	var got []time.Duration
	for range 8 {
		d = restartDelay(d, time.Second)
		got = append(got, d)
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute}; !slices.Equal(got, want) {
		t.Errorf("%v", got)
	}
	if restartDelay(time.Minute, 11*time.Minute) != time.Second {
		t.Error("a daemon that ran ten minutes is started again soon")
	}
}
