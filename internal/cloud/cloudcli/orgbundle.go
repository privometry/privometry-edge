package cloudcli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/cloud/keyset"
	"github.com/privometry/privometry-edge/internal/keystore"
)

const bundleUsage = `Usage: privometry bundle <status|sync>

  status   show the organization's policy bundle this device enforces
  sync     fetch the newest bundle now (the daemon does this every 5 minutes)

The bundle carries your organization's policies, signed with your region's
policy key, and your organization's entitlements. This device merges its
policies with the built-in packs and your own user and repo policies, and
keeps enforcing the bundle it holds while the cloud is unreachable.
`

func bundleCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "status" && args[0] != "sync") {
		fmt.Fprint(stderr, bundleUsage)
		return 2
	}
	env, err := accountEnv()
	if err != nil {
		return fail(stderr, err)
	}
	id, err := enroll.Load(env)
	if err != nil {
		return fail(stderr, err)
	}
	if id == nil {
		fmt.Fprintln(stdout, "This device is not enrolled, so it has no organization bundle. Run privometry login, or privometry enroll with a token.")
		return 1
	}
	now := accountNow()
	if args[0] == "sync" {
		keys, err := keystore.Open(env, id.Keystore)
		if err != nil {
			return fail(stderr, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		res, err := bundles.Sync(ctx, accountHTTP(), env, keys, now)
		if err != nil {
			return fail(stderr, err)
		}
		if res.Changed {
			fmt.Fprintf(stdout, "Fetched bundle version %d; the daemon applies it to the next agent action.\n", res.Held.Bundle.Version)
		} else {
			fmt.Fprintf(stdout, "Bundle version %d is the newest.\n", res.Held.Bundle.Version)
		}
		return 0
	}
	held, err := bundles.Load(env, now)
	if err != nil {
		return fail(stderr, err)
	}
	if held == nil {
		fmt.Fprintln(stdout, "No organization bundle yet; run privometry bundle sync, or wait for the daemon to fetch one.")
		return 1
	}
	b := held.Bundle
	fmt.Fprintf(stdout, "Bundle:       version %d (%s)\n", b.Version, b.BundleID)
	fmt.Fprintf(stdout, "Signed:       %s, expires %s\n", b.CreatedAt.Format("2 Jan 2006 15:04 MST"), b.ExpiresAt.Format("2 Jan 2006 15:04 MST"))
	var names []string
	for _, s := range b.Sources {
		names = append(names, s.Name+"@"+s.Version)
	}
	if len(names) == 0 {
		names = []string{"none"}
	}
	monitor := 0
	for _, r := range b.Rules {
		if r.Mode == bundles.BundleRuleModeMonitor {
			monitor++
		}
	}
	fmt.Fprintf(stdout, "Policies:     %s\n", strings.Join(names, ", "))
	fmt.Fprintf(stdout, "Rules:        %d (%d in monitor mode)\n", len(b.Rules), monitor)
	ent := held.Entitlements
	until := "no end"
	if ent.ValidUntil != nil {
		until = ent.ValidUntil.Format("2 Jan 2006")
	}
	fmt.Fprintf(stdout, "Entitlements: %s (%s), until %s\n", ent.Edition, ent.State, until)
	if ks, err := keyset.Load(env); err == nil && ks != nil {
		how := "verified against this build's root keys"
		if ks.Pinned {
			how = "pinned at enrollment"
		}
		fmt.Fprintf(stdout, "Key set:      version %d, %s\n", ks.Keys.Version, how)
	}
	if held.Expired {
		fmt.Fprintln(stdout, "The bundle has expired. It is still enforced; run privometry bundle sync, or check that this device can reach the cloud.")
	}
	return 0
}
