package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSplitCommandLine(t *testing.T) {
	for in, want := range map[string][]string{
		`agy --dangerously-skip-permissions`:                  {"agy", "--dangerously-skip-permissions"},
		`"C:\Program Files\Antigravity\agy.exe"  --mode auto`: {`C:\Program Files\Antigravity\agy.exe`, "--mode", "auto"},
		`node /usr/local/bin/gemini --approval-mode "yolo"`:   {"node", "/usr/local/bin/gemini", "--approval-mode", "yolo"},
		"": nil,
	} {
		if got := SplitCommandLine(in); !slices.Equal(got, want) {
			t.Errorf("SplitCommandLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMain lets the test binary stand in for a long-running child process.
func TestMain(m *testing.M) {
	if os.Getenv("PRIVOMETRY_TEST_SLEEP") != "" {
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Processes sees this test binary, with its parent and a start time that
// ProcessInfo agrees with.
func TestProcessesSeesThisProcess(t *testing.T) {
	procs, err := Processes()
	if err != nil {
		t.Skipf("no process list here: %v", err)
	}
	self := filepath.Base(os.Args[0])
	i := slices.IndexFunc(procs, func(p Process) bool { return p.PID == os.Getpid() })
	if i < 0 || !strings.HasSuffix(procs[i].Args[0], self) {
		t.Fatalf("%s (pid %d) not among %d processes", self, os.Getpid(), len(procs))
	}
	me := procs[i]
	if me.PPID != os.Getppid() || me.Start.IsZero() || time.Since(me.Start) > time.Hour {
		t.Errorf("listed as %+v", me)
	}
	info, err := ProcessInfo(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if info.Key() != me.Key() || info.PPID != me.PPID {
		t.Errorf("ProcessInfo %+v, listing %+v", info, me)
	}
	chain := Ancestors(os.Getpid(), 4, nil)
	if len(chain) == 0 || chain[0].PID != os.Getpid() || len(chain) > 1 && chain[1].PID != os.Getppid() {
		t.Errorf("ancestors %+v", chain)
	}
	if boot, err := BootTime(); err != nil || !boot.Before(me.Start.Add(time.Second)) {
		t.Errorf("boot time %v, %v; started %v", boot, err, me.Start)
	}
}

func TestProcessCwdAndEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not readable on Windows")
	}
	// The variable must be in a child's starting environment: a process's
	// own later setenv is not visible to the OS. The child is this test
	// binary: macOS hides the arguments and environment of its own platform
	// binaries (/bin/sleep), not of other programs, hardened or not.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "PRIVOMETRY_TEST_DIR=/tmp/privometry-env-test", "PRIVOMETRY_TEST_SLEEP=1")
	cmd.Dir = os.TempDir()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	env, err := ProcessEnv(cmd.Process.Pid, []string{"PRIVOMETRY_TEST_DIR"})
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1 || env["PRIVOMETRY_TEST_DIR"] != "/tmp/privometry-env-test" {
		t.Errorf("env %v", env)
	}
	cwd, err := ProcessCwd(cmd.Process.Pid)
	want, _ := filepath.EvalSymlinks(os.TempDir())
	got, _ := filepath.EvalSymlinks(cwd)
	if err != nil || got != filepath.Clean(want) {
		t.Errorf("cwd %q, %v; want %q", cwd, err, want)
	}
}

func TestAncestorsStopsAtLimitAndLoops(t *testing.T) {
	parents := map[int]int{40: 30, 30: 20, 20: 20}
	info := func(pid int) (Process, error) {
		pp, ok := parents[pid]
		if !ok {
			return Process{}, ErrNoProcessInfo
		}
		return Process{PID: pid, PPID: pp}, nil
	}
	if got := Ancestors(40, 2, info); len(got) != 2 || got[1].PID != 30 {
		t.Errorf("limit: %+v", got)
	}
	if got := Ancestors(40, 10, info); len(got) != 3 || got[2].PID != 20 {
		t.Errorf("loop: %+v", got)
	}
}
