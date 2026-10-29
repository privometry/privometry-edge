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
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/community"
	"github.com/privometry/privometry-edge/internal/definitions"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/policy/rulepack"
)

const trustUsage = `Usage: privometry trust <add|list|remove> [flags]

  add <keys.json|https URL>   Trust a publisher's keys to sign community packs
  list                        Show the publisher keys you trust
  remove <publisher|key ID>   Stop trusting a publisher or one key; its packs stop loading

Flags:
`

const packsUsage = `Usage: privometry packs <install|list|remove|keygen|sign> [flags]

  install <file|https URL>    Verify a signed community pack, run its own tests, and install it
  list                        Show installed community packs and whether each still verifies
  remove <publisher/name>     Uninstall a community pack
  keygen --publisher NAME     Make a publisher key: NAME.key (keep it secret) and NAME.keyset.json (share it)
  sign <folder> --key FILE    Test a pack folder and sign it as <publisher>-<name>-<version>.pack.json

Installed rule packs apply only to policies that extend them, for example
  extends: [acme/k8s-guard@^1]
Installed detector packs run with the built-in detectors.

Flags:
`

// communityStore is a test hook.
var communityStore = func(env platform.Env) (*community.Store, error) { return community.Open(env) }

// availablePacks returns the built-in rule packs plus the community packs
// installed for env that verify now. Packs that do not are left out and,
// with warn set, reported there.
func availablePacks(env platform.Env, warn io.Writer) ([]rulepack.Pack, error) {
	packs, err := policy.BuiltinPacks()
	if err != nil {
		return nil, err
	}
	s, err := communityStore(env)
	if err != nil {
		return packs, nil
	}
	more, errs := s.RulePacks(time.Now(), buildinfo.Version)
	if warn != nil {
		for _, e := range errs {
			fmt.Fprintf(warn, "privometry: community pack left out: %v\n", e)
		}
	}
	return append(packs, more...), nil
}

// readSource reads a local file, or fetches an https URL.
func readSource(src string) ([]byte, error) {
	if strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return definitions.Fetch(ctx, &http.Client{Timeout: 30 * time.Second}, src)
	}
	return os.ReadFile(src) //nolint:gosec // reads the pack path the user passed on the command line
}

func trustCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, trustUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("trust "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, trustUsage); fs.PrintDefaults() }
	yes := fs.Bool("yes", false, "add: do not ask for confirmation (you checked the fingerprints another way)")
	format := fs.String("format", "table", "list: table or json")
	if err := parseInterspersed(fs, args[1:]); err != nil {
		return 2
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	s, err := communityStore(env)
	if err != nil {
		return fail(stderr, err)
	}
	switch sub {
	case "add":
		if fs.NArg() != 1 {
			fs.Usage()
			return 2
		}
		raw, err := readSource(fs.Arg(0))
		if err != nil {
			return fail(stderr, err)
		}
		keys, err := community.PublisherKeys(raw, time.Now())
		if err != nil {
			return fail(stderr, err)
		}
		for _, k := range keys {
			fmt.Fprintf(stdout, "Publisher %s\n  key         %s\n  fingerprint %s\n  valid from  %s\n", k.Publisher, k.KeyID, k.Fingerprint(), k.NotBefore)
			if k.NotAfter != nil {
				fmt.Fprintf(stdout, "  valid until %s\n", k.NotAfter)
			}
		}
		if !*yes {
			fmt.Fprintln(stdout, "\nA trusted key can sign packs that decide what your agents may do. Compare the fingerprint with one the publisher announced.")
			answer, err := prompter.Line("Trust these keys? [y/N] ")
			if err != nil {
				return fail(stderr, err)
			}
			if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
				fmt.Fprintln(stdout, "Nothing changed.")
				return 1
			}
		}
		if err := s.Trust(keys); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "Trusted %d key(s). Install packs with privometry packs install.\n", len(keys))
		return 0
	case "list":
		keys, err := s.Trusted()
		if err != nil {
			return fail(stderr, err)
		}
		if *format == "json" {
			type row struct {
				community.Key
				Fingerprint string `json:"fingerprint"`
			}
			rows := []row{}
			for _, k := range keys {
				rows = append(rows, row{k, k.Fingerprint()})
			}
			return writeJSON(stdout, rows)
		}
		if len(keys) == 0 {
			fmt.Fprintln(stdout, "No publisher keys trusted. Add one with privometry trust add <keys.json>.")
			return 0
		}
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "PUBLISHER\tKEY\tFINGERPRINT\tADDED")
		for _, k := range keys {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.Publisher, k.KeyID, k.Fingerprint(), k.AddedAt.Format("2006-01-02"))
		}
		w.Flush()
		return 0
	case "remove":
		if fs.NArg() != 1 {
			fs.Usage()
			return 2
		}
		n, err := s.Untrust(fs.Arg(0))
		if errors.Is(err, community.ErrNotInstalled) {
			fmt.Fprintf(stderr, "privometry: no trusted key matches %s\n", fs.Arg(0))
			return 1
		}
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "Removed %d key(s). Packs they signed no longer load; restart privometryd (privometry daemon restart) so it drops them now.\n", n)
		return 0
	}
	fmt.Fprint(stderr, trustUsage)
	return 2
}

func packsCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, packsUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("packs "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, packsUsage); fs.PrintDefaults() }
	format := fs.String("format", "table", "list: table or json")
	noRestart := fs.Bool("no-restart", false, "install, remove: do not restart privometryd")
	publisher := fs.String("publisher", "", "keygen: your publisher name, the first part of your pack IDs")
	keyFile := fs.String("key", "", "sign: your publisher key file from keygen")
	kind := fs.String("kind", "", "sign: rules or detectors (default: detectors when the folder has detectors/)")
	out := fs.String("out", "", "keygen: file name prefix; sign: output file")
	if err := parseInterspersed(fs, args[1:]); err != nil {
		return 2
	}
	switch sub {
	case "keygen":
		return packsKeygen(*publisher, *out, stdout, stderr)
	case "sign":
		if fs.NArg() != 1 || *keyFile == "" {
			fs.Usage()
			return 2
		}
		return packsSign(fs.Arg(0), *keyFile, *kind, *out, stdout, stderr)
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	s, err := communityStore(env)
	if err != nil {
		return fail(stderr, err)
	}
	switch sub {
	case "install":
		if fs.NArg() != 1 {
			fs.Usage()
			return 2
		}
		raw, err := readSource(fs.Arg(0))
		if err != nil {
			return fail(stderr, err)
		}
		in, err := s.Install(raw, community.InstallOptions{Now: time.Now(), SensorVersion: buildinfo.Version})
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "Installed %s %s (%s pack, signed by %s).\n", in.ID, in.Version, in.Kind, in.SignedBy)
		if in.Kind == string(community.DocumentKindRules) {
			fmt.Fprintf(stdout, "It applies to policies that extend it: extends: [%s@^%s]\n", in.ID, strings.SplitN(in.Version, ".", 2)[0])
		}
		if !*noRestart {
			restartDaemon(env, "packs", "the new pack", stdout, stderr)
		}
		return 0
	case "remove":
		if fs.NArg() != 1 {
			fs.Usage()
			return 2
		}
		if err := s.Remove(fs.Arg(0)); err != nil {
			if errors.Is(err, community.ErrNotInstalled) {
				fmt.Fprintf(stderr, "privometry: %s is not installed\n", fs.Arg(0))
				return 1
			}
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "Removed %s.\n", fs.Arg(0))
		if !*noRestart {
			restartDaemon(env, "packs", "the pack removed", stdout, stderr)
		}
		return 0
	case "list":
		list, err := s.List(time.Now(), buildinfo.Version)
		if err != nil {
			return fail(stderr, err)
		}
		if *format == "json" {
			if list == nil {
				list = []community.Installed{}
			}
			return writeJSON(stdout, list)
		}
		if len(list) == 0 {
			fmt.Fprintln(stdout, "No community packs installed.")
			return 0
		}
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "PACK\tKIND\tVERSION\tSTATUS")
		for _, in := range list {
			status := "ok"
			if in.Problem != "" {
				status = "not loaded: " + in.Problem
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", in.ID, in.Kind, in.Version, status)
		}
		w.Flush()
		return 0
	}
	fmt.Fprint(stderr, packsUsage)
	return 2
}

func packsKeygen(publisher, out string, stdout, stderr io.Writer) int {
	if publisher == "" {
		fmt.Fprintln(stderr, "privometry: packs keygen needs --publisher")
		return 2
	}
	if out == "" {
		out = publisher
	}
	seed, keySet, key, err := community.NewSeed(publisher, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return fail(stderr, err)
	}
	keyPath, setPath := out+".key", out+".keyset.json"
	for _, p := range []string{keyPath, setPath} {
		if _, err := os.Stat(p); err == nil { //nolint:gosec // output paths come from the user's own --out flag
			return fail(stderr, fmt.Errorf("%s exists; choose another --out", p))
		}
	}
	if err := os.WriteFile(keyPath, seed, 0o600); err != nil { //nolint:gosec // output paths come from the user's own --out flag
		return fail(stderr, err)
	}
	if err := os.WriteFile(setPath, keySet, 0o644); err != nil { //nolint:gosec // the key set is public and meant to be shared
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Wrote %s (secret: keep it out of repos) and %s (share it).\nKey %s\nFingerprint %s\n", keyPath, setPath, key.KeyID, key.Fingerprint())
	return 0
}

func packsSign(dir, keyFile, kind, out string, stdout, stderr io.Writer) int {
	if kind == "" {
		kind = string(community.DocumentKindRules)
		if info, err := os.Stat(filepath.Join(dir, "detectors")); err == nil && info.IsDir() { //nolint:gosec // the pack folder the user passed on the command line
			kind = string(community.DocumentKindDetectors)
		}
	}
	doc, err := community.Build(dir, community.DocumentKind(kind), time.Now())
	if err != nil {
		return fail(stderr, err)
	}
	seed, err := os.ReadFile(keyFile) //nolint:gosec // the key file the user passed on the command line
	if err != nil {
		return fail(stderr, err)
	}
	signed, err := community.Sign(doc, seed)
	if err != nil {
		return fail(stderr, err)
	}
	// Check it the way an installing sensor will, with the signing key trusted.
	scratch, err := os.MkdirTemp("", "privometry-sign-")
	if err != nil {
		return fail(stderr, err)
	}
	defer os.RemoveAll(scratch)
	s, err := community.Open(platform.Env{GOOS: "linux", Home: scratch, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return scratch
		}
		return ""
	}})
	if err != nil {
		return fail(stderr, err)
	}
	var d community.Document
	if err := json.Unmarshal(doc, &d); err != nil {
		return fail(stderr, err)
	}
	key, err := community.SeedKey(seed, strings.SplitN(d.ID, "/", 2)[0], time.Now().Add(-time.Minute))
	if err == nil {
		err = s.Trust([]community.Key{key})
	}
	if err != nil {
		return fail(stderr, err)
	}
	if _, err := s.Install(signed, community.InstallOptions{Now: time.Now(), SensorVersion: buildinfo.Version}); err != nil {
		return fail(stderr, err)
	}
	if out == "" {
		out = community.SignedFile(d.ID, d.Version)
	}
	if err := os.WriteFile(out, signed, 0o644); err != nil { //nolint:gosec // a signed pack is public and meant to be published
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Signed %s %s (%s pack, %d files) into %s.\n", d.ID, d.Version, d.Kind, len(d.Files), out)
	return 0
}

// parseInterspersed parses flags wherever they appear, so both
// "sign --key k dir" and "sign dir --key k" work.
func parseInterspersed(fs *flag.FlagSet, args []string) error {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return fs.Parse(append([]string{"--"}, positional...))
}

func writeJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 2
	}
	return 0
}
