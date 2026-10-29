// Command privometryd is the Privometry daemon. It answers privometry-hook over a
// user-only socket and keeps the local timeline. See internal/daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/community"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/definitions"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(buildinfo.String("privometryd"))
		return
	}
	fs := flag.NewFlagSet("privometryd", flag.ExitOnError)
	logPath := fs.String("log", "", "append the log to this file instead of standard error (the Windows task sets it)")
	home := fs.String("home", "", "data folder, as PRIVOMETRY_HOME (the Windows task has no environment of its own)")
	superviseFlag := fs.Bool("supervise", false, "run privometryd and start it again when it stops (the Windows Run key fallback sets it)")
	_ = fs.Parse(os.Args[1:]) // ExitOnError: a bad flag exits
	if *home != "" {
		os.Setenv("PRIVOMETRY_HOME", *home)
	}
	out := os.Stderr
	if *logPath != "" {
		f, err := openLog(*logPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "privometryd:", err)
			os.Exit(1)
		}
		defer f.Close()
		// A crash is written there too: the Windows build has no console.
		_ = debug.SetCrashOutput(f, debug.CrashOptions{})
		out = f
	}
	logger := slog.New(slog.NewTextHandler(out, nil))
	if *superviseFlag {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := supervise(ctx, os.Args[1:], logger); err != nil {
			logger.Error("privometryd -supervise stopped", "err", err)
			os.Exit(1)
		}
		return
	}
	if err := run(logger); err != nil {
		logger.Error("privometryd stopped", "err", err)
		os.Exit(1)
	}
}

// openLog opens the log for appending in a folder private to the user.
func openLog(path string) (*os.File, error) {
	if err := platform.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func run(logger *slog.Logger) error {
	env, err := platform.CurrentEnv()
	if err != nil {
		return err
	}
	dir, err := definitions.Dir(env)
	if err != nil {
		return err
	}
	dopts := definitions.Options{Dir: dir, SensorVersion: buildinfo.Version}
	reg, ast, err := definitions.LoadAdapters(dopts)
	if err != nil {
		return err
	}
	detectors, dst, err := definitions.LoadDetectors(dopts)
	if err != nil {
		return err
	}
	for _, st := range []definitions.Status{ast, dst} {
		logger.Info("definitions", "kind", st.Kind, "source", st.Source, "set_version", st.SetVersion)
		if st.Problem != "" {
			logger.Warn("signed definitions not used", "kind", st.Kind, "problem", st.Problem)
		}
	}
	packs, err := policy.BuiltinPacks()
	if err != nil {
		return err
	}
	// Community packs installed with privometry packs install, verified again
	// now; a pack that no longer verifies is left out.
	if store, err := community.Open(env); err == nil {
		more, errs := store.RulePacks(time.Now(), buildinfo.Version)
		packs = append(packs, more...)
		moreDetectors, derrs := store.DetectorPacks(time.Now(), buildinfo.Version)
		detectors = append(detectors, moreDetectors...)
		for _, e := range append(errs, derrs...) {
			logger.Warn("community pack left out", "err", e)
		}
		for _, p := range more {
			logger.Info("community rule pack", "id", p.Manifest.ID, "version", p.Manifest.Version)
		}
		for _, p := range moreDetectors {
			logger.Info("community detector pack", "id", p.Manifest.ID, "version", p.Manifest.Version)
		}
	}
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Detectors: detectors, Logger: logger, AdapterSetVersion: ast.SetVersion})
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx)
}
