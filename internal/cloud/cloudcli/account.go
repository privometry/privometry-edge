package cloudcli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/account"
	"github.com/privometry/privometry-edge/internal/buildinfo"
	cloudaccount "github.com/privometry/privometry-edge/internal/cloud/account"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/termio"
)

// Swapped by tests.
var (
	accountEnv                  = platform.CurrentEnv
	accountHTTP                 = func() *http.Client { return &http.Client{Timeout: 30 * time.Second} }
	prompter    termio.Prompter = termio.TTY{}
	openConsole                 = termio.OpenBrowser
	accountNow                  = time.Now
)

const loginUsage = `Usage: privometry login --email ADDRESS (--invite LINK | --org SLUG | --create-org NAME --slug SLUG) [flags]

Sign this machine up with your Privometry organization, then enroll it:

  --invite LINK                   join from the invitation you were emailed (its link or pit_ token)
  --org SLUG                      add this machine to your account in an organization you belong to
  --create-org NAME --slug SLUG   create an organization; you become its owner

Privometry emails a code to confirm the address. This machine then makes your
sign-in key, which a PIN you choose unlocks. The PIN never leaves the machine
and cannot be recovered; if you forget it, an admin resets your account.
privometry console asks for it to sign you in to the console. Last, the
machine enrolls with your organization.

Flags:
`

const consoleUsage = `Usage: privometry console [--print]

Signs you in to the Privometry console with your sign-in key, after asking for
its PIN, and opens the console in your browser. The sign-in link works once,
for 60 seconds.

Flags:
`

func loginCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, loginUsage); fs.PrintDefaults() }
	email := fs.String("email", "", "your work email")
	invite := fs.String("invite", "", "invitation link or token")
	org := fs.String("org", "", "slug of an organization you belong to")
	createOrg := fs.String("create-org", "", "name of a new organization")
	slug := fs.String("slug", "", "slug of the new organization (3 to 40 lowercase letters, digits and hyphens)")
	name := fs.String("name", "", "your name, for a new account (asked when missing)")
	label := fs.String("label", "", "name of this machine's key (default: the host name)")
	api := fs.String("api", envOr("PRIVOMETRY_ACCOUNT_API", account.DefaultAPI), "account API of your organization's region")
	store := fs.String("keystore", "auto", "where to keep keys: auto, keychain or file")
	noEnroll := fs.Bool("no-enroll", false, "sign up only; do not enroll this device")
	replace := fs.Bool("replace", false, "replace the account this machine is signed up with")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	purposes := 0
	for _, v := range []string{*invite, *org, *createOrg} {
		if v != "" {
			purposes++
		}
	}
	if *email == "" || purposes != 1 || (*createOrg != "") != (*slug != "") {
		fs.Usage()
		return 2
	}
	env, err := accountEnv()
	if err != nil {
		return fail(stderr, err)
	}
	if existing, err := account.LoadState(env); err == nil && !*replace {
		return fail(stderr, fmt.Errorf("this machine is already signed up as %s in %s; use --replace to sign up again", existing.Email, existing.OrgName))
	}
	keys, err := keystore.Open(env, *store)
	if err != nil {
		return fail(stderr, err)
	}
	if *label == "" {
		if *label = termio.HostName(); *label == "" {
			*label = "privometry-cli"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	client := &account.Client{BaseURL: strings.TrimSuffix(*api, "/"), HTTP: accountHTTP(), UserAgent: "privometry/" + buildinfo.Version}

	device := enroll.Device(env)
	start := cloudaccount.RegistrationStart{Email: *email,
		Client: cloudaccount.Client{Kind: cloudaccount.ClientKindCLI, OS: device.OS, Arch: device.Arch, SensorVersion: device.SensorVersion}}
	switch {
	case *invite != "":
		start.Purpose, start.InvitationToken = cloudaccount.RegistrationPurposeAcceptInvitation, invitationToken(*invite)
	case *org != "":
		start.Purpose, start.OrgSlug = cloudaccount.RegistrationPurposeAddDevice, *org
	default:
		start.Purpose = cloudaccount.RegistrationPurposeCreateOrganization
		start.Organization = &cloudaccount.RegistrationStartOrganization{Name: *createOrg, Slug: *slug}
	}
	reg, err := client.StartRegistration(ctx, start)
	if err != nil {
		return fail(stderr, explainAccount(err))
	}
	fmt.Fprintf(stdout, "If %s can join, a code is on its way there. It works for 10 minutes.\n", *email)

	challenge, err := verifyCode(ctx, client, reg.RegistrationID, stdout)
	if err != nil {
		return fail(stderr, err)
	}
	if strings.TrimSuffix(challenge.Audience, "/") != client.BaseURL {
		return fail(stderr, fmt.Errorf("the account API answered for %s, not %s; check --api", challenge.Audience, client.BaseURL))
	}
	fmt.Fprintf(stdout, "Email confirmed: %s (%s), role %s.\n", challenge.Organization.Name, challenge.Organization.Slug, challenge.Role)
	displayName := *name
	if challenge.UserID == "" && displayName == "" {
		if displayName, err = prompter.Line("Your name: "); err != nil {
			return fail(stderr, err)
		}
	}

	pin, err := choosePIN(stdout)
	if err != nil {
		return fail(stderr, err)
	}
	priv, err := account.NewCLIKey()
	if err != nil {
		return fail(stderr, err)
	}
	sealed, err := account.Seal(priv, pin)
	if err != nil {
		return fail(stderr, err)
	}
	spki, err := account.SPKI(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return fail(stderr, err)
	}
	thumbprint := account.Thumbprint(spki)
	proof, err := account.SignProof(priv, thumbprint, cloudaccount.AccountProof{Purpose: cloudaccount.AccountProofPurposeRegister,
		Audience: challenge.Audience, Challenge: challenge.Challenge, RegistrationID: challenge.RegistrationID,
		PublicKeySHA256: thumbprint, IssuedAt: contract.At(accountNow())})
	if err != nil {
		return fail(stderr, err)
	}
	// The sealed key is stored before the account API hears of it, so a registered key is never lost.
	if err := keys.Put(account.KeyName, sealed); err != nil {
		return fail(stderr, err)
	}
	if displayName == "" {
		displayName = *email
	}
	complete := cloudaccount.RegistrationComplete{Credential: cloudaccount.RegistrationCompleteCredential{
		Type: cloudaccount.CredentialTypeCLIKey, Label: truncate(*label, 80), Algorithm: cloudaccount.KeyAlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(spki), Protection: cloudaccount.KeyProtectionSoftware, Proof: proof}}
	if challenge.UserID == "" {
		complete.DisplayName = displayName
	}
	result, err := client.CompleteRegistration(ctx, challenge.RegistrationID, complete)
	if err != nil {
		return fail(stderr, explainAccount(err))
	}
	state := &account.State{APIBaseURL: client.BaseURL, Region: result.Region, OrgID: result.OrgID, OrgName: challenge.Organization.Name,
		OrgSlug: challenge.Organization.Slug, UserID: result.UserID, Email: *email, Role: string(result.Role),
		CredentialID: result.CredentialID, Keystore: keys.Kind(), RegisteredAt: accountNow().UTC()}
	if err := account.SaveState(env, state); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "Signed up as %s in %s. Your sign-in key (%s) is in %s, encrypted with your PIN.\n",
		*email, state.OrgName, result.CredentialID, describe(keys))

	if *noEnroll || result.Enrollment == nil {
		return 0
	}
	id, err := enroll.Enroll(ctx, accountHTTP(), result.Enrollment.EdgeBaseURL, result.Enrollment.EnrollmentToken, env, keys, accountNow())
	if err != nil {
		fmt.Fprintf(stderr, "This device is not enrolled: %v\nRun privometry login --org %s --replace when the edge API is reachable.\n", err, state.OrgSlug)
		return 1
	}
	fmt.Fprintf(stdout, "Enrolled this device (%s) in region %s; its certificate expires %s.\n", id.DeviceID, id.Region,
		id.CertificateExpiresAt.Format("2 Jan 2006"))
	return 0
}

// verifyCode asks for the emailed code until it verifies. An empty answer asks
// for a new code.
func verifyCode(ctx context.Context, client *account.Client, registrationID string, stdout io.Writer) (*cloudaccount.RegistrationChallenge, error) {
	for {
		code, err := prompter.Line("Code (press Enter for a new one): ")
		if err != nil {
			return nil, err
		}
		code = strings.TrimSpace(code)
		if code == "" {
			if _, err := client.ResendCode(ctx, registrationID); err != nil {
				var p *account.Problem
				if errors.As(err, &p) && p.Kind() == "rate-limited" {
					fmt.Fprintf(stdout, "No new code yet; try again in %s seconds.\n", p.RetryAfter)
					continue
				}
				return nil, explainAccount(err)
			}
			fmt.Fprintln(stdout, "A new code is on its way.")
			continue
		}
		challenge, err := client.VerifyCode(ctx, registrationID, code)
		var p *account.Problem
		if errors.As(err, &p) && p.Kind() == "invalid-code" {
			left := ""
			if p.CodeAttemptsLeft != nil {
				left = fmt.Sprintf(" (%d attempts left)", *p.CodeAttemptsLeft)
			}
			fmt.Fprintf(stdout, "%s%s.\n", strings.TrimSuffix(p.Detail, "."), left)
			continue
		}
		if err != nil {
			return nil, explainAccount(err)
		}
		return challenge, nil
	}
}

func choosePIN(stdout io.Writer) (string, error) {
	fmt.Fprintf(stdout, "Choose a PIN for your sign-in key (at least %d characters; a passphrase is stronger).\n", account.PINMinLength)
	for range 3 {
		pin, err := prompter.Secret("PIN: ")
		if err != nil {
			return "", err
		}
		if err := account.CheckPIN(pin); err != nil {
			fmt.Fprintln(stdout, strings.ToUpper(err.Error()[:1])+err.Error()[1:]+".")
			continue
		}
		again, err := prompter.Secret("PIN again: ")
		if err != nil {
			return "", err
		}
		if again == pin {
			return pin, nil
		}
		fmt.Fprintln(stdout, "The PINs differ.")
	}
	return "", errors.New("no PIN chosen")
}

func consoleCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, consoleUsage); fs.PrintDefaults() }
	printOnly := fs.Bool("print", false, "print the one-time sign-in link instead of opening a browser")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	env, err := accountEnv()
	if err != nil {
		return fail(stderr, err)
	}
	state, err := account.LoadState(env)
	if err != nil {
		return fail(stderr, err)
	}
	keys, err := keystore.Open(env, state.Keystore)
	if err != nil {
		return fail(stderr, err)
	}
	sealed, err := keys.Get(account.KeyName)
	if errors.Is(err, keystore.ErrNotFound) {
		return fail(stderr, errors.New("this machine's sign-in key is missing; run privometry login --replace"))
	}
	if err != nil {
		return fail(stderr, err)
	}
	var priv ed25519.PrivateKey
	for attempt := 1; ; attempt++ {
		pin, err := prompter.Secret("PIN for " + state.Email + ": ")
		if err != nil {
			return fail(stderr, err)
		}
		key, err := account.Open(sealed, pin)
		if err == nil {
			priv = key
			break
		}
		if !errors.Is(err, account.ErrWrongPIN) || attempt == 3 {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, "Wrong PIN.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := &account.Client{BaseURL: state.APIBaseURL, HTTP: accountHTTP(), UserAgent: "privometry/" + buildinfo.Version}
	challenge, err := client.SignInChallenge(ctx, state.CredentialID)
	if err != nil {
		return fail(stderr, explainAccount(err))
	}
	if strings.TrimSuffix(challenge.Audience, "/") != strings.TrimSuffix(state.APIBaseURL, "/") {
		return fail(stderr, fmt.Errorf("the account API answered for %s, not %s", challenge.Audience, state.APIBaseURL))
	}
	proof, err := account.SignProof(priv, state.CredentialID, cloudaccount.AccountProof{Purpose: cloudaccount.AccountProofPurposeSignIn,
		Audience: challenge.Audience, Challenge: challenge.Challenge, ChallengeID: challenge.ChallengeID,
		CredentialID: state.CredentialID, IssuedAt: contract.At(accountNow())})
	if err != nil {
		return fail(stderr, err)
	}
	result, err := client.SignIn(ctx, cloudaccount.SignInRequest{ChallengeID: challenge.ChallengeID, Method: cloudaccount.CredentialTypeCLIKey,
		CredentialID: state.CredentialID, Proof: proof})
	if err != nil {
		return fail(stderr, explainAccount(err))
	}
	if result.SignInLink == nil {
		return fail(stderr, errors.New("the account API sent no sign-in link"))
	}
	if *printOnly {
		fmt.Fprintln(stdout, result.SignInLink.URL)
		return 0
	}
	if err := openConsole(result.SignInLink.URL); err != nil {
		fmt.Fprintf(stdout, "Could not open a browser (%v). Open this link within 60 seconds:\n%s\n", err, result.SignInLink.URL)
		return 0
	}
	fmt.Fprintln(stdout, "Opened the console in your browser.")
	return 0
}

// explainAccount turns account API problems into what the person can do about them.
func explainAccount(err error) error {
	var p *account.Problem
	if !errors.As(err, &p) {
		return err
	}
	switch p.Kind() {
	case "registration-expired":
		return errors.New("the registration ended (it expired, or too many codes were wrong); run privometry login again")
	case "slug-taken":
		return errors.New("that slug is taken; choose another --slug")
	case "add-device-disabled":
		return errors.New("your organization adds devices only through an admin; ask an admin to reset your account, then use the invitation they send")
	case "rate-limited":
		return fmt.Errorf("too many attempts; try again in %s seconds", p.RetryAfter)
	case "proof-rejected":
		return fmt.Errorf("the account API did not accept this machine's key: %s", p.Detail)
	}
	return err
}

// invitationToken accepts the emailed link (https://console…/join#t=pit_…) or the bare token.
func invitationToken(s string) string {
	if i := strings.Index(s, "#t="); i >= 0 {
		return s[i+3:]
	}
	return strings.TrimSpace(s)
}

func describe(s keystore.Store) string {
	switch s.Kind() {
	case keystore.KindMacOS:
		return "the macOS keychain"
	case keystore.KindSecretService:
		return "the system keyring"
	case keystore.KindDPAPI:
		return "a file sealed to your Windows account (DPAPI)"
	}
	return "a file only you can read"
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
