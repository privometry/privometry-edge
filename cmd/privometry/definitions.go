package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/daemon/service"
	"github.com/privometry/privometry-edge/internal/definitions"
	"github.com/privometry/privometry-edge/internal/platform"
)

const definitionsUsage = `Usage: privometry definitions <status|update|install> [flags]

Adapter definitions (where each agent keeps its config and how its hooks talk)
and detector packs ship inside Privometry. Newer sets signed with Privometry's
release key can replace them without a new release. A set is used only when
its signature verifies, it is newer than the set built in, and everything in
it loads; otherwise the built-in set stays in use.

  privometry definitions status            show which sets are in use, and why
  privometry definitions update            download and install the latest signed sets
  privometry definitions install FILE...   install signed sets from files (offline)

The daemon is restarted after an install so it picks up the new sets.

Flags:
`

// definitionOptions locates installed sets for env.
func definitionOptions(env platform.Env) definitions.Options {
	dir, _ := definitions.Dir(env)
	return definitions.Options{Dir: dir, SensorVersion: buildinfo.Version}
}

// loadAdapters returns the adapter definitions in use: an installed signed
// set when one is valid, else the built-in definitions.
func loadAdapters(env platform.Env) (*registry.Registry, error) {
	reg, _, err := definitions.LoadAdapters(definitionOptions(env))
	return reg, err
}

// loadDetectors returns the detector packs in use: Privometry's (built in
// or from a signed set) and the community detector packs installed that
// verify now.
func loadDetectors(env platform.Env) ([]*content.Pack, error) {
	packs, _, err := definitions.LoadDetectors(definitionOptions(env))
	if err != nil {
		return nil, err
	}
	if s, err := communityStore(env); err == nil {
		more, _ := s.DetectorPacks(time.Now(), buildinfo.Version)
		packs = append(packs, more...)
	}
	return packs, nil
}

func definitionsCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("definitions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, definitionsUsage); fs.PrintDefaults() }
	format := fs.String("format", "table", "status output: table or json")
	baseURL := fs.String("url", "", "update: folder URL holding adapters.json and detectorpacks.json (default: $PRIVOMETRY_DEFINITIONS_URL, else the latest release)")
	noRestart := fs.Bool("no-restart", false, "install, update: do not restart privometryd")
	if len(args) == 0 {
		fs.Usage()
		return 2
	}
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	opts := definitionOptions(env)

	switch sub {
	case "status":
		return definitionsStatus(definitions.Statuses(opts), *format, stdout)
	case "install":
		if fs.NArg() == 0 {
			fmt.Fprintln(stderr, "privometry definitions install: name one or more signed set files")
			return 2
		}
		var sets [][]byte
		for _, f := range fs.Args() {
			raw, err := os.ReadFile(f)
			if err != nil {
				return fail(stderr, err)
			}
			sets = append(sets, raw)
		}
		return installSets(env, opts, sets, false, *noRestart, stdout, stderr)
	case "update":
		base := *baseURL
		if base == "" {
			base = env.Getenv("PRIVOMETRY_DEFINITIONS_URL")
		}
		if base == "" {
			base = definitions.DefaultBaseURL
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		client := &http.Client{Timeout: time.Minute}
		var sets [][]byte
		for _, k := range definitions.Kinds {
			raw, err := definitions.Fetch(ctx, client, strings.TrimRight(base, "/")+"/"+k.File())
			if err != nil {
				return fail(stderr, fmt.Errorf("%s: %w", k.Label(), err))
			}
			sets = append(sets, raw)
		}
		return installSets(env, opts, sets, true, *noRestart, stdout, stderr)
	}
	fmt.Fprintf(stderr, "privometry definitions: unknown subcommand %q\n\n", sub)
	fs.Usage()
	return 2
}

// installSets installs each set. When fromUpdate is set, a set that is not
// newer than the one in use is reported as current rather than as an error.
func installSets(env platform.Env, opts definitions.Options, sets [][]byte, fromUpdate, noRestart bool, stdout, stderr io.Writer) int {
	installed, failed := 0, false
	for _, raw := range sets {
		k, _ := definitions.KindOf(raw)
		st, err := definitions.Install(opts, raw)
		switch {
		case errors.Is(err, definitions.ErrNotNewer) && fromUpdate:
			fmt.Fprintf(stdout, "%s are up to date.\n", k.Label())
		case err != nil:
			label := "privometry definitions"
			if k != "" {
				label += ": " + k.Label()
			}
			fmt.Fprintf(stderr, "%s: %v\n", label, err)
			failed = true
		default:
			fmt.Fprintf(stdout, "Installed %s set %d (published %s).\n", strings.ToLower(k.Label()), st.SetVersion, st.PublishedAt)
			for _, kept := range st.Kept {
				fmt.Fprintf(stdout, "  kept built in: %s\n", kept)
			}
			installed++
		}
	}
	if installed > 0 && !noRestart {
		restartDaemon(env, "definitions", "the new definitions", stdout, stderr)
	}
	if failed {
		return 1
	}
	return 0
}

// restartDaemon restarts the daemon service, if installed, so it loads what
// a command changed.
func restartDaemon(env platform.Env, cmd, what string, stdout, stderr io.Writer) {
	privometryd, _ := sibling("", "privometryd")
	sopts := service.Options{Env: env, Privometryd: privometryd, Run: serviceRunner, UID: os.Getuid()}
	plan, err := service.For(sopts)
	if err != nil || !service.Check(plan, sopts).Installed {
		fmt.Fprintln(stdout, "privometryd is not installed as a service; restart it yourself if it runs.")
		return
	}
	if err := service.Restart(sopts); err != nil {
		fmt.Fprintf(stderr, "privometry %s: restarting privometryd: %v (run privometry daemon restart)\n", cmd, err)
		return
	}
	if waitForDaemon(env, 5*time.Second) {
		fmt.Fprintf(stdout, "privometryd restarted with %s.\n", what)
	}
}

func definitionsStatus(sts []definitions.Status, format string, stdout io.Writer) int {
	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sts); err != nil {
			return 2
		}
		return 0
	}
	for _, st := range sts {
		if st.Source == "signed" {
			fmt.Fprintf(stdout, "%s: signed set %d, published %s (built in: %d)\n", st.Kind.Label(), st.SetVersion, st.PublishedAt, st.BuiltIn)
		} else {
			fmt.Fprintf(stdout, "%s: built-in set %d\n", st.Kind.Label(), st.SetVersion)
		}
		if st.Problem != "" {
			fmt.Fprintf(stdout, "  %s\n", st.Problem)
		}
		for _, kept := range st.Kept {
			fmt.Fprintf(stdout, "  kept built in: %s\n", kept)
		}
	}
	return 0
}
