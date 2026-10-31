package cloudcli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/cloud/upload"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// DefaultEdge is the edge API of the India region. The host is a placeholder
// until it is registered.
const DefaultEdge = "https://in.api.privometry.dev/edge/v1"

const enrollUsage = `Usage: privometry enroll --token TOKEN [--edge URL] [--keystore auto|keychain|file]

Enrolls this device with an enrollment token from an admin or your MDM, without
signing a person up: the device syncs with the organization and belongs to no
person until someone runs privometry login on it. People signing up use
privometry login, which enrolls the device itself.

Flags:
`

const deviceUsage = `Usage: privometry device <status|renew>

  status   show this device's enrollment
  renew    get a new certificate, for a new device key, before the old one expires
`

func enrollCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, enrollUsage); fs.PrintDefaults() }
	token := fs.String("token", "", "enrollment token (pet_...)")
	edge := fs.String("edge", envOr("PRIVOMETRY_EDGE_API", DefaultEdge), "edge API of your organization's region")
	store := fs.String("keystore", "auto", "where to keep keys: auto, keychain or file")
	if err := fs.Parse(args); err != nil || *token == "" || fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	env, err := accountEnv()
	if err != nil {
		return fail(stderr, err)
	}
	keys, err := keystore.Open(env, *store)
	if err != nil {
		return fail(stderr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, err := enroll.Enroll(ctx, accountHTTP(), *edge, strings.TrimSpace(*token), env, keys, accountNow())
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Enrolled this device (%s) in region %s; its certificate expires %s.\n", id.DeviceID, id.Region,
		id.CertificateExpiresAt.Format("2 Jan 2006"))
	return 0
}

func deviceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "status" && args[0] != "renew") {
		fmt.Fprint(stderr, deviceUsage)
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
		fmt.Fprintln(stdout, "This device is not enrolled. Run privometry login, or privometry enroll with a token from an admin.")
		return 1
	}
	if args[0] == "renew" {
		keys, err := keystore.Open(env, id.Keystore)
		if err != nil {
			return fail(stderr, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if id, err = enroll.Renew(ctx, accountHTTP(), env, keys); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "Renewed: a new device key and a certificate that expires %s.\n", id.CertificateExpiresAt.Format("2 Jan 2006"))
		return 0
	}
	fmt.Fprintf(stdout, "Device:      %s\nOrganization: %s\nRegion:      %s\nEdge API:    %s\nCertificate: expires %s\n",
		id.DeviceID, id.OrgID, id.Region, id.APIBaseURL, id.CertificateExpiresAt.Format("2 Jan 2006 15:04 MST"))
	if id.UserID != "" {
		fmt.Fprintf(stdout, "Person:      %s\n", id.UserID)
	}
	if id.KeySetPinned {
		fmt.Fprintln(stdout, "Key set:     pinned at enrollment (this build has no root keys to verify it with)")
	}
	if dir, err := env.DataDir(); err == nil {
		if store, err := timeline.OpenReadOnly(filepath.Join(dir, daemon.DBFile)); err == nil {
			cursor, _ := upload.Cursor(store)
			if b, err := store.BacklogAfter(cursor); err == nil {
				waiting := "all events uploaded"
				if b.Events > 0 {
					waiting = fmt.Sprintf("%d events waiting, oldest from %s", b.Events, b.Oldest.Local().Format("2 Jan 2006 15:04"))
				}
				fmt.Fprintf(stdout, "Uploads:     %s\n", waiting)
			}
			store.Close()
		}
	}
	if left := id.CertificateExpiresAt.Sub(accountNow()); left < enroll.RenewBefore {
		fmt.Fprintf(stdout, "The certificate expires in %d days; run privometry device renew.\n", int(left.Hours()/24))
	}
	return 0
}
