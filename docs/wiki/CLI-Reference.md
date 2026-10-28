# CLI Reference

The main executable is `privometry`. Exit code `0` means success, `1` means a policy/finding/health condition was detected, and `2` means invalid usage or a runtime error.

## `privometry scan`

Discovers agents and reports risky configuration.

```sh
privometry scan [--format table|json|sarif] [--repo PATH] [--no-repo]
                 [--no-machine] [--fail-on SEVERITY] [--output FILE]
                 [--changed FILE|-]
```

- `--repo`: scan a specific repository; otherwise the containing Git repository is used.
- `--no-repo`: scan machine configuration only.
- `--no-machine`: scan repository configuration only, suitable for CI.
- `--fail-on low|medium|high|critical`: return exit code 1 at or above the threshold.
- `--output`: write the report to a file.
- `--changed`: the files a merge or pull request changes (`git diff --name-status` output or one path per line; `-` reads stdin). Changed agent files and the repo policy become `agent_file_changed` findings, and every changed text file is scanned with the content detectors.

Allowlist entries in the repo policy (and, for a machine scan, the user policy) drop accepted content findings; the report counts them.

CI examples:

```sh
privometry scan --no-machine --format sarif --fail-on high --output privometry.sarif
git diff --name-status --no-renames origin/main...HEAD | privometry scan --no-machine --changed - --fail-on high
```

On GitHub, the action in `action/` runs these checks on every pull request; see `action/README.md`.

## `privometry daemon`

Manages the per-user daemon service.

```sh
privometry daemon install|uninstall|status|restart
  [--privometryd PATH] [--dry-run] [--format table|json]
```

Service installation currently supports launchd on macOS and systemd user services on Linux.

## `privometry guard`

Registers or removes native agent hooks.

```sh
privometry guard install|uninstall|status
  [--agent AGENT] [--hook PATH] [--dry-run] [--format table|json]
```

Agent identifiers are `claude_code`, `codex_cli`, and `cursor`. Installation preserves unrelated agent hooks.

## `privometry timeline`

Queries redacted local events.

```sh
privometry timeline [--agent AGENT] [--verdict allow|ask|deny]
  [--type TYPE] [--search TEXT] [--since DURATION] [--limit N]
  [--format table|json] [--follow] [--web] [--port PORT] [--no-open]
```

Event types are `action`, `config_change`, `integrity`, `fail_mode`, `inventory`, and `content_finding`. The web view binds to loopback and uses a per-run access token.

## `privometry policy test`

Tests policy files or rule-pack directories and can explain synthetic actions.

```sh
privometry policy test [--layer user|repo|org] [--tests DIR] [PATH...]
privometry policy test --command COMMAND [--untrusted] [--agent AGENT]
privometry policy test --read PATH
privometry policy test --write PATH
privometry policy test --fetch URL
```

With no path, Privometry looks for `.privometry/policy.yaml` in the current repository and `~/.privometry/policy.yaml`.

## `privometry doctor`

Checks binary consistency, permissions, service and daemon health, a real synthetic hook decision, fail modes, installed hooks, policy, spool state, and integrity alerts.

```sh
privometry doctor [--format table|json] [--no-probe]
privometry doctor --bundle [--output FILE]
```

Inspect diagnostic archives before sharing even though the bundle is redacted.

## `privometry update`

Checks or installs a signed release:

```sh
privometry update --check
privometry update [--manifest URL]
```

`PRIVOMETRY_UPDATE_URL` supplies an alternate manifest. Development builds and builds without release trust keys refuse self-update.

## `privometry definitions`

Shows or replaces the adapter definitions and detector packs in use with newer sets signed by the release key:

```sh
privometry definitions status [--format table|json]
privometry definitions update [--url URL] [--no-restart]
privometry definitions install [--no-restart] FILE...
```

`PRIVOMETRY_DEFINITIONS_URL` supplies an alternate folder holding `adapters.json` and `detectorpacks.json`. A set is used only when its signature verifies, it is newer than the built-in set, and everything in it loads; otherwise the built-in set stays in use. See `docs/definitions.md`.

## `privometry memory`

The versions of agents' memory and instruction files the daemon kept, and going back to one:

```sh
privometry memory list [--format table|json]
privometry memory history FILE [--format table|json]
privometry memory show FILE --version N
privometry memory diff FILE [--version N]
privometry memory restore FILE (--version N | --last-good) [--yes]
```

Versions stay on this machine. `--last-good` is the newest version that scans clean now; a restore keeps the current content as a version first. Needs `privometryd` running. See `docs/content-scanning.md`.

## `privometry trust` and `privometry packs`

Community rule and detector packs, signed by their publishers:

```sh
privometry trust add [--yes] KEYS.json|URL
privometry trust list [--format table|json]
privometry trust remove PUBLISHER|KEY-ID
privometry packs install [--no-restart] FILE|URL
privometry packs list [--format table|json]
privometry packs remove [--no-restart] PUBLISHER/NAME
privometry packs keygen --publisher NAME [--out PREFIX]
privometry packs sign FOLDER --key FILE [--kind rules|detectors] [--out FILE]
```

A pack installs only when a trusted key of its own publisher signed it and it passes its own tests or samples; installed rule packs apply to policies that `extends` them, installed detector packs run with the built-in detectors. See `docs/community-packs.md`.

## `privometry mcp`

Runs local stdio MCP servers through `privometry-mcp-shim`, which checks each tool call with the daemon and scans tool descriptions:

```sh
privometry mcp status [--agent AGENT] [--format table|json]
privometry mcp wrap [--agent AGENT] [--dry-run] [--shim PATH]
privometry mcp unwrap [--agent AGENT] [--dry-run]
```

Only user-level MCP configs are edited (Claude Code `~/.claude.json`, Cursor `~/.cursor/mcp.json`, Codex `~/.codex/config.toml`); remote servers and repo configs are left alone. Restart the agents after wrapping. See `docs/mcp-shim.md`.

## `privometry login`

Signs this machine up with your organization and enrolls it:

```sh
privometry login --email ADDRESS --invite LINK                  # join from an invitation
privometry login --email ADDRESS --org SLUG                     # add this machine to your account
privometry login --email ADDRESS --create-org NAME --slug SLUG  # create an organization (you become owner)
  [--name NAME] [--label LABEL] [--api URL] [--keystore auto|keychain|file] [--no-enroll] [--replace]
```

It asks for the emailed code (Enter sends a new one), your name for a new account, and a PIN for your sign-in key, then enrolls the device. The PIN never leaves the machine and cannot be recovered; an admin reset replaces the key. Exit code 1 means you are signed up but the device is not enrolled. See `docs/account.md`.

## `privometry console`

Signs you in to the console with your sign-in key after asking for its PIN, and opens the console in your browser:

```sh
privometry console [--print]
```

`--print` prints the one-time sign-in link (valid 60 seconds) instead of opening a browser.

## `privometry enroll`

Enrolls this device with a token from an admin or an MDM rollout, without signing a person up (the device belongs to no person until someone runs `privometry login` on it):

```sh
privometry enroll --token pet_... [--edge URL] [--keystore auto|keychain|file]
```

## `privometry device`

```sh
privometry device status   # device ID, organization, region, edge API, certificate expiry, upload backlog
privometry device renew    # a new device key and certificate, over mutual TLS with the current one
```

Certificates last 30 days; `status` suggests renewing in the last 10, and the daemon renews on its own in that window. `status` also says when the region's key set was pinned at enrollment because this build has no root keys.

## `privometry bundle`

```sh
privometry bundle status   # the organization bundle this device enforces: version, policies, rules, entitlements, key set
privometry bundle sync     # fetch the newest bundle now
```

An enrolled daemon fetches the bundle every 5 minutes. A bundle is used only when it is signed by the region's policy key, is for this device's organization, is not older than the one held and has not expired; otherwise the device keeps the bundle it holds. An expired bundle stays in force until a new one arrives. The bundle's policies are merged with the built-in packs and the user and repo policies, so `privometry policy test` and `doctor` show the same rules the daemon enforces.

## `privometry version`

Prints the version, commit, and build date injected by the release build.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `PRIVOMETRY_HOME` | Override the runtime data directory |
| `PRIVOMETRY_HOOK_TIMEOUT_MS` | Override hook-to-daemon timeout |
| `PRIVOMETRY_UPDATE_URL` | Override signed release manifest URL |
| `PRIVOMETRY_EDGE_API` | Edge API for `privometry enroll` (default `https://in.api.privometry.dev/edge/v1`) |
| `PRIVOMETRY_ACCOUNT_API` | Account API for `privometry login` (default `https://in.api.privometry.dev/account/v1`) |
| `PRIVOMETRY_RECORD_DIR` | Development-only hook recorder output directory |
| `NO_COLOR` | Disable terminal color |

`PRIVOMETRY_HOOK_PROBE` is an internal, one-time doctor token and is not a supported operator setting.
