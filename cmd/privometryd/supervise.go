package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/platform"
)

// supervise runs privometryd without -supervise and starts it again whenever
// it exits, as the logon task's restart settings would. A Run key starts it at
// logon where Windows refused the task (internal/daemon/service). It holds
// privometryd-supervisor.lock, whose PID privometry daemon uses to stop it.
func supervise(ctx context.Context, args []string, logger *slog.Logger) error {
	env, err := platform.CurrentEnv()
	if err != nil {
		return err
	}
	dir, err := env.DataDir()
	if err != nil {
		return err
	}
	if err := platform.EnsurePrivateDir(dir); err != nil {
		return err
	}
	release, err := daemon.Lock(dir, "privometryd-supervisor.lock")
	if err != nil {
		return err
	}
	defer release()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	child := withoutSupervise(args)
	var delay time.Duration
	for {
		started := time.Now()
		err := exec.CommandContext(ctx, self, child...).Run()
		if ctx.Err() != nil {
			return nil
		}
		delay = restartDelay(delay, time.Since(started))
		logger.Warn("privometryd stopped; starting it again", "err", err, "in", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// withoutSupervise is args without the -supervise flag.
func withoutSupervise(args []string) []string {
	var out []string
	for _, a := range args {
		switch strings.TrimLeft(a, "-") {
		case "supervise", "supervise=true":
			continue
		}
		out = append(out, a)
	}
	return out
}

// restartDelay doubles the wait while privometryd keeps stopping soon after
// it starts, up to a minute, and starts over once it ran for ten minutes.
func restartDelay(prev, ran time.Duration) time.Duration {
	if prev == 0 || ran >= 10*time.Minute {
		return time.Second
	}
	return min(2*prev, time.Minute)
}
