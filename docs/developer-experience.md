# Timeline, doctor and updates

The M5 tools for living with Privometry day to day: seeing what agents did, checking that protection works, and staying up to date.

## privometry timeline

```bash
privometry timeline                          # the last 50 events, oldest first
privometry timeline --verdict deny --since 24h
privometry timeline --search terraform --agent cursor
privometry timeline --type integrity         # config changes Privometry noticed
privometry timeline --follow                 # keep printing new events
privometry timeline --format json
privometry timeline --web                    # open the timeline in a browser
```

Rows show the time, agent, outcome, the kind of row (Shell, Read, Write, Delete, Fetch, Search, MCP or Subagent for a tool call; Config, Memory, Integrity or Finding otherwise) (ALLOWED, AUTO, ASKED, BLOCKED, WOULD DENY, CONFIG, ALERT, BLOCKED* for a closed fail mode, FAILMODE), the full command or path, and why: the rule IDs, or the reason the daemon recorded (`ext.x_privometry_reason`). `--search` matches the full command and rule IDs. Colors appear only on a terminal and respect `NO_COLOR`.

The CLI asks the daemon (`events` IPC operation) and reads `privometry.db` read-only when the daemon is down. A daemon older than the CLI is reported as such, not as stopped: `privometry daemon status` compares the operations the daemon reports (`Status.Ops`) with the ones this CLI uses and says to run `privometry daemon restart`.

### The web timeline

`privometry timeline --web` serves the local guard (`ui/timeline-web`, embedded in the binary) and opens the browser. It follows the "Local guard" mode of the console and local guard prototype: a sidebar with Privometry's status on this machine ("Guarding 2 agents", or why not), five views, a Live/Paused switch and a light or dark theme, collapsing to a menu on a phone.

| View | Shows |
|---|---|
| Timeline | A banner when privometryd is down, outdated or an agent is not hooked; each agent's hook state and activity; today's tally; every action by day with filters, search, keyboard navigation (`j`, `k`, Enter, `/`), paging and new actions as they arrive. Each row is tagged with its kind (Shell, MCP, Write, …) and opens to the explanation, the rule and its layer, the MCP server and tool for MCP calls, the decision time, what the agent actually received when it cannot express the verdict (Codex gets a block for an ask), and the stored event |
| Sessions | Each agent session with its actions, asks and blocks, and whether it read untrusted content or injected instructions |
| Scan | A machine scan, as `privometry scan`: what is worth fixing (posture and content findings), each agent with its hook state, MCP servers, memory files. "Scan now" reruns it |
| Policy | The policy layers (organization, repo, your overrides with a "View file" for `~/.privometry/policy.yaml`, built-in packs), what happens when no rule matches or Privometry cannot decide in time, and every rule in effect |
| Device | This machine, the daemon, what the timeline stores and for how long, and the `privometry doctor` checks |

The prototype's controls that need a backend Privometry Free does not have are left out rather than faked: stopping a session, requesting an exception, and changing what the timeline captures or how long it keeps it.

The page shows full commands, so the server (`internal/webui`) is locked down:

- listens on `127.0.0.1` only, on a free port unless `--port` is given, until Ctrl+C;
- a random 256-bit token in the printed URL is swapped on first load for an `HttpOnly`, `SameSite=Strict` cookie named per port, and the token is dropped from the address bar;
- the `Host` header must be `127.0.0.1:<port>` or `localhost:<port>`, which stops DNS rebinding;
- only `GET` and `HEAD`; `Sec-Fetch-Site: cross-site` or `same-site` requests are refused;
- `Content-Security-Policy: default-src 'none'` with only the page's own script, style and API; no inline script or style, and the script builds the page with `textContent`, never `innerHTML` (tests check both);
- `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.

The API is read-only: `GET /api/events?show=all|exc|ask|deny&agent=&search=&before_seq=&after_seq=&limit=`, `GET /api/summary`, `GET /api/sessions`, and `GET /api/view/<agents|scan|policy|device>` (computed by the CLI and cached for 10 seconds to a minute; `?fresh=1` recomputes). A page whose server was restarted stops polling and asks for the new link.

## Config integrity

Every minute the daemon hashes the agent config files it watches (`internal/daemon/integrity.go`): each agent's hook file, its user and managed settings, and its user MCP server lists (only the server map, so unrelated edits to the same file are ignored). Hashes live in the `config_hashes` table. A change records a `config_change` event (`detected_by: file_watcher`). When the file held Privometry's hook before and no longer does, or the hook entry changed, it also records an `integrity` event (`hook_removed` or `hook_modified`), shown as ALERT in the timeline and by `privometry doctor`. A file that starts turning the agent's hooks off (`disableAllHooks`, Codex `[features] hooks = false`) records `hooks_disabled`; project settings files are watched for the workspaces agents worked in recently. Silent agents and a stopped or uninstalled sensor are described in `docs/daemon.md`.

## privometry doctor

```bash
privometry doctor              # checks, with a fix for each problem; exit 1 if any fail
privometry doctor --format json
privometry doctor --no-probe   # skip the test decision
privometry doctor --bundle     # also write privometry-doctor-<time>.zip
```

| Check | Fails or warns when |
|---|---|
| Binaries | `privometryd` or `privometry-hook` is missing next to `privometry`, or reports another version |
| Data folder | `~/.privometry` (or `$PRIVOMETRY_HOME`) or a file in it can be read by other users |
| Service | the launchd or systemd service is missing, stopped, or out of date |
| Daemon | privometryd does not answer, or is older than the CLI |
| Test decision | `privometry-hook` does not block `rm -rf ~`, or only by fail mode, or over budget |
| Fail modes | catastrophic actions would not be blocked with the daemon down |
| Offline decisions | fail-mode decisions sit in `spool.jsonl` without being imported |
| One row per agent | its hook is missing, partial or stale, or Codex has not been trusted yet |
| Policy | a policy file is ignored, has diagnostics, or does not compile |
| Alerts | integrity events in the last 24 hours |

The test decision runs the real `privometry-hook` with a Claude Code `PreToolUse` call for `rm -rf ~`. To keep fake activity out of the timeline, doctor first asks the daemon for a one-time probe token (`probe` IPC operation, valid for 30 seconds); the hook passes it on (`PRIVOMETRY_HOOK_PROBE`) and the daemon decides as usual but records nothing. A static token cannot be planted in an agent's environment to hide its actions: unknown or spent tokens are ignored. With the daemon down there is nothing to check the token against, so the hook's fail-mode decision is spooled like any other.

### The diagnostic bundle

`--bundle` writes a zip (mode 0600, never overwriting) with the checks, versions, daemon status, each agent's hook state, fail modes, the user and repo policy files with the merged policy, the service file, the last 2,000 lines of `privometryd.log`, and the last 500 events in their redacted, uploadable form. It leaves out the unredacted commands (`target_clear`), the contents of `spool.jsonl` (which holds them), and agent config files (which can hold API keys). Everything passes through `redact.Secrets`: secrets are replaced, the home folder becomes `~`, other users' names are hidden, and the local user name in events becomes `<user>`. A `README.txt` inside says all of this.

## privometry update

```bash
privometry update --check   # say whether a newer release exists
privometry update           # download, verify, install, restart privometryd
```

Releases are `privometry.release/v1` manifests (`specs/release/v1`) in DSSE envelopes, payload type `application/vnd.privometry.release+json`, signed by a `release` key. The manifest URL defaults to the latest GitHub release asset `release.json` (`https://github.com/privometry/privometry-edge/releases/latest/download/release.json`), which `.github/workflows/release.yml` builds and signs; `--manifest` or `PRIVOMETRY_UPDATE_URL` override it. `internal/update` installs a release only when:

1. the signature verifies against the release key set embedded in the binary (`internal/trust/keys/release-keys.json`, shared with signed definition sets);
2. the manifest validates and has not passed `expires_at`, so an old manifest cannot be replayed forever;
3. its version is newer than the running one by semver precedence (downgrades and reinstalls are refused, and development builds never update);
4. the download for this OS and architecture, fetched over HTTPS with no redirect off HTTPS, has exactly the declared size and SHA-256;
5. the archive holds the declared binaries as regular files at its top level (links, folders, other files and path tricks are ignored);
6. the new `privometry` runs here and reports the manifest's version.

Binaries are staged next to the installed ones and swapped in with renames, restoring the old ones if any swap fails; then the service restarts so privometryd runs the new build. Homebrew and Scoop installs are refused with the package manager's command instead.

**No release keys ship yet.** Until the owner of the release key is decided, `internal/trust/keys/release-keys.json` is absent and `privometry update` refuses with "this build has no release signing keys". The updater is tested with the conformance `release` test key, and `specs/conformance/signatures` has `release-valid` and `release-signed-by-policy-key` vectors for the Java side.

## Known gaps

- The integrity check runs every minute, so a hook removed and restored within a minute goes unnoticed; file-system notifications are a later improvement.
- `privometry doctor` reads the repo policy of the current folder only.
- `privometry update` replaces binaries while agents may be running hooks; each rename is atomic, but an agent can see the new `privometry-hook` with the old daemon for a moment (the IPC protocol is unchanged, so this is safe today).
- The web timeline polls every 2 seconds instead of streaming.
