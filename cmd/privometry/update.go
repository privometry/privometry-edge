package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/daemon/service"
	"github.com/privometry/privometry-edge/internal/update"
)

const updateUsage = `Usage: privometry update [flags]

Install the latest signed Privometry release in place of this one: privometry, privometryd
and privometry-hook, then restart the daemon. Only releases signed with Privometry's
release key, newer than this version, and matching their published digest
are installed.

  privometry update --check    only say whether a newer release exists
  privometry update            download, verify and install it

Flags:
`

func updateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, updateUsage); fs.PrintDefaults() }
	check := fs.Bool("check", false, "only check for a newer release")
	manifest := fs.String("manifest", "", "release manifest URL (default: $PRIVOMETRY_UPDATE_URL, else the stable channel)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	if *manifest == "" {
		*manifest = env.Getenv("PRIVOMETRY_UPDATE_URL")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	opts := update.Options{ManifestURL: *manifest, Current: buildinfo.Version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}

	rel, art, err := update.Check(ctx, opts)
	switch {
	case errors.Is(err, update.ErrUpToDate):
		fmt.Fprintf(stdout, "privometry %s is the latest release.\n", buildinfo.Version)
		return 0
	case errors.Is(err, update.ErrDowngrade):
		fmt.Fprintf(stdout, "privometry %s is newer than the published release (%s); nothing to do.\n", buildinfo.Version, rel.Version)
		return 0
	case errors.Is(err, update.ErrNoReleaseKeys):
		fmt.Fprintln(stderr, "privometry update: this build has no release signing keys, so it cannot verify a download and will not install one.")
		fmt.Fprintln(stderr, "Update with the package manager or build you installed Privometry from.")
		return 1
	case errors.Is(err, update.ErrDevBuild):
		fmt.Fprintf(stderr, "privometry update: this is a development build (%s); build from source again, or install a release.\n", buildinfo.Version)
		return 1
	case err != nil:
		return fail(stderr, err)
	}
	if *check {
		fmt.Fprintf(stdout, "privometry %s is available (you have %s). Run privometry update to install it.\n", rel.Version, buildinfo.Version)
		if rel.NotesURL != "" {
			fmt.Fprintf(stdout, "Release notes: %s\n", rel.NotesURL)
		}
		return 0
	}

	dir, err := update.InstallDir()
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Downloading privometry %s (%.1f MB)…\n", rel.Version, float64(art.Size)/(1<<20))
	staged, err := update.Stage(ctx, opts, art, dir, rel.Version)
	if err != nil {
		return fail(stderr, err)
	}
	if err := staged.Install(); err != nil {
		return fail(stderr, err)
	}
	names := make([]string, 0, len(staged.Files))
	for n := range staged.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(stdout, "Updated %s to %s in %s.\n", strings.Join(names, ", "), rel.Version, strings.Replace(dir, env.Home, "~", 1))

	// The running daemon is still the old build until it restarts.
	privometryd, _ := sibling("", "privometryd")
	sopts := service.Options{Env: env, Privometryd: privometryd, Run: serviceRunner, UID: os.Getuid()}
	plan, err := service.For(sopts)
	if err != nil || !service.Check(plan, sopts).Installed {
		fmt.Fprintln(stdout, "privometryd is not installed as a service; restart it yourself if it runs.")
		return 0
	}
	if err := service.Restart(sopts); err != nil {
		fmt.Fprintf(stderr, "privometry update: restarting privometryd: %v (run privometry daemon restart)\n", err)
		return 1
	}
	if waitForDaemon(env, 5*time.Second) {
		fmt.Fprintln(stdout, "privometryd restarted on the new version.")
		return 0
	}
	fmt.Fprintln(stdout, "privometryd did not answer after the restart; run privometry doctor.")
	return 1
}
