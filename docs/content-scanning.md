# Content scanning

How Privometry finds leaked credentials and instructions aimed at agents (PRD SCAN-01 to SCAN-16): the contracts, the detector engine and packs, the daemon's checks before and after each tool call, memory file hashing, the rules on the new facts, and `privometry scan` at rest.

```
text an agent sends, writes or loads
        │
        ▼
internal/content (detector packs) ──► findings ──► content_finding events (timeline)
        │
        └──► Summary ──► policy facts: secret_detected, injection_detected, hidden_content
                                       (+ injection_seen from the session, target_class from the path)
                                       └──► Cedar rules decide ask or deny
```

## Contracts

| Spec | What changed |
|---|---|
| `event-schema/v1` | New event type `content_finding` (detector, category, severity, confidence, source, `secret_type`, `location` with a salted `path_hash`, salted `fingerprint`, `action_taken`; never a value or a raw path). `action.secret_types` and `context.injection_seen` |
| `policy/v1` | Facts `secret_detected` (kinds, or `any`), `injection_detected`, `injection_seen`, `hidden_content`, `target_class`; the same five attributes in `privometry.cedarschema`; example `content-scanning.yaml` with 10 shared verdict vectors; `allowlist` entries (SCAN-09) |
| `rulepack/v1` | Rule tests can set the five facts |
| `detectorpack/v1` (new) | `privometry.detectorpack/v1` manifests and `privometry.detectors/v1` files; `privometry.detectorpack_set/v1`, the signed set of Privometry's packs (SCAN-09) |
| `adapter/v1` | `memory_files` per agent: tier, kind (`instructions`, `rules`, `memory`), format, paths, `nested`, `imports`, `written_by_agent` |

## Memory and instruction files

`adapter-defs/*.yaml` list where each agent keeps them:

| Agent | Files |
|---|---|
| Claude Code | Managed, user (`~/.claude/CLAUDE.md`) and project `CLAUDE.md` (also nested and in `.claude/`), `CLAUDE.local.md`, `~/.claude/rules/` and `.claude/rules/`, automatic memory in `~/.claude/projects/*/memory/*.md` |
| Codex CLI | `~/.codex/AGENTS.md`, `AGENTS.override.md`, project `AGENTS.md` (nested), experimental `~/.codex/memories/` |
| Cursor | `.cursor/rules/*.mdc` (moved from `config_tiers`), `AGENTS.md`, legacy `.cursorrules`; user rules and memories live in the app, not in files |
| Gemini CLI | `~/.gemini/GEMINI.md` (global context, where `save_memory` appends), project `GEMINI.md` (nested) |
| Antigravity | `~/.gemini/AGENTS.md`, `~/.gemini/GEMINI.md`, `~/.gemini/config/AGENTS.md` and `GEMINI.md`, rule folders `~/.gemini/config/rules/` and `~/.gemini/antigravity-cli/rules/`; project `AGENTS.md`, `GEMINI.md` and `.agents/` copies (nested), `.agents/rules/*.md` |
| Copilot CLI | `~/.copilot/copilot-instructions.md`, `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `AGENTS.md` (nested) |

The extractors set `target_class` for every file an action touches: `memory_file` (the paths above, plus `GEMINI.md` and Copilot's instruction files), `agent_config` (every config tier and MCP source, skills, `.privometry/policy.yaml`), `code` (anything else in the repo) or `other`. The hook client cannot load adapter definitions, so the patterns are built in; `TestTargetClassMatchesAdapterDefs` checks every adapter path against them.

## Detector packs

`detectorpacks/` ships three packs, loaded with `content.Load(detectorpacks.FS)`. A newer signed set can replace them without a release (see "Signed detector packs" below):

| Pack | Detectors | Finds |
|---|---|---|
| `privometry/credentials` 1.0.0 | 18 | AWS, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, Google, GCP service account and npm credentials, private keys, JWTs, passwords in connection strings, bearer tokens, random values assigned to secret-named variables |
| `privometry/injection` 1.1.0 | 12 | Ignore-previous-instructions, fake system messages, hide-from-user, skip-approvals, disable-protection, download-and-run, send-secrets-out; data carried out in image and link URLs (SCAN-13): placeholders in image, link and HTML `src`/`href` URLs, image URLs that already hold encoded data, and instructions to put secrets or the conversation into a URL |
| `privometry/hidden-content` 1.0.0 | 6 | Invisible and direction-changing characters, Unicode tag text, variation-selector runs, private-use characters, instructions in HTML comments, encoded instructions, text pushed off-screen |

Each detector has `samples.match` and `samples.no_match`; `content.Check` (run by `detectorpacks/detectorpacks_test.go`) requires every detector to fire on each match sample and stay quiet on each other one, for every source it applies to. Sample credentials are split with `{{}}` so secret scanners never see a contiguous token. Known example values (AWS's documented keys) are in `allow` lists.

Detector and rule packs have separate namespaces, and their names make the distinction explicit: `privometry/credentials` detects credential material, while the `privometry/secrets` rule pack decides what to do with secret-related actions.

## The engine

`internal/content`:

- **Kinds.** `pattern` (RE2), `entropy` (a pattern picks values, kept when random enough), `unicode` (hidden character classes; emoji joiners, right-to-left marks and a single emoji variation selector are ignored), `structure` (HTML comments, base64 and hex blobs that decode to readable text, mid-line whitespace gaps, Markdown image URLs), each optionally filtered by a pattern on the content.
- **Keywords.** One Aho-Corasick pass finds every detector's keywords; a pattern runs only on short windows around its hits (128 bytes before, 384 after, within the line), so most of a large input is never examined and Go's regexp uses its fast backtracker.
- **Findings.** Detector, category, severity, confidence, source, line, a masked excerpt for the local timeline (credentials show their first four characters and length; hidden characters are shown as `<U+200B>` and tag text is decoded), and for credentials an `hmac-sha256` fingerprint under the engine's salt. When a provider detector and a generic one find the same value, only the provider finding is kept. At most 20 findings per detector per scan.
- **Summary.** `content.Summarize` turns findings into the policy facts: sorted secret kinds, the strongest injection level, and whether anything is hidden.
- **Budget (SCAN-11).** `PreActionLimit` is 64 KB. `ScanWithin` takes a deadline and runs credential detectors first; on the hook path the daemon decides on what was found in time and finishes the scan after the action, raising findings instead of blocking.

Measured on an M-series Mac, all 32 shipped detectors on 64 KB:

| Content | p50 | p95 |
|---|---|---|
| Go source | 1.2 ms | 1.6 ms |
| Markdown documentation | 3.0 ms | 3.6 ms |
| YAML, JSON Schema, JavaScript | 1.1–1.4 ms | 1.1–1.7 ms |
| Adversarial: a keyword on every line | 8 ms | 10 ms (bounded by `ScanWithin`) |

## In the daemon

**Before each decision** (SCAN-04, SCAN-11) the daemon scans what the tool call carries, once per call: the command, the URL, an MCP call's arguments (flattened to `key: value` lines, so JSON escaping cannot hide characters) and written content (`tool_targets.*.content` in the adapter, or the lines an `apply_patch` adds). The scan has a 5 ms budget measured from its start; anything not reached is scanned after the reply and raises findings with `action_taken: none`. The summary becomes the facts `secret_detected`, `injection_detected` and `hidden_content` for every request of the call, and `action.secret_types` on the action event.

**After each tool call** the daemon scans the tool's output in the background (up to 256 KB; writes are skipped, their output echoes the input). Injected or safety-weakening instructions of medium or high level, or exfiltration instructions, mark the session `injection_seen` for the rest of the session; that fact and `context.injection_seen` are on every later decision.

**Findings** become `content_finding` events: detector, category, severity, confidence, source, `secret_type` and salted fingerprint for credentials, location (path class, salted path hash, line), and `action_taken` from the decision (`blocked`, `asked`, `none`). The local timeline keeps `path:line` and the masked excerpt in `target_clear`; nothing else holds a value. At most 20 per tool call. The salt is a random per-device key in the timeline's state until the device enrolls with an organization.

**Memory files** (SCAN-02) are hashed every minute with the other watched files: user and managed memory files of every agent, and the project files at the root of each workspace an agent worked in during the last 24 hours. A file seen for the first time is scanned (`source: memory_file`); a changed one records a `config_change` event with `holds` `instructions`, `rules` or `memory` and `changed_by`:

- `agent` when an agent session was allowed to write that file through a hooked tool less than two minutes earlier, or when the agent's own `PostToolUse` reports the write (checked at once, which also covers nested files the watcher does not list). The two-minute window is the confirmed P1 default and can be revisited if operational evidence shows false attribution;
- `person` otherwise.

The new content is scanned again and its findings recorded.

## Rules on the content facts

| Pack | Rule | Verdict | When |
|---|---|---|---|
| `privometry/secrets` 1.1.0 | `secret-in-command` | ask | A literal credential in a shell command |
| | `secret-written-to-file` | ask | A credential written into a file other than `.env` or `.env.local` |
| | `secret-in-mcp-arguments` | ask | A credential passed to an MCP tool |
| `privometry/exfiltration` 1.1.0 | `secret-to-network` | deny | A fetch carrying a credential |
| | `secret-in-network-command` | deny | `curl`, `wget`, `nc` and similar with a literal credential |
| `privometry/agent-instructions` 1.0.0 (new) | `ask-instruction-edit` | ask | Writing or deleting an instruction file (by tool or shell redirect); automatic memory folders are exempt |
| | `block-memory-edit-after-injection` | deny | Any memory or instruction edit once the session has `injection_seen` (SCAN-03) |
| | `ask-safety-weakening-write` | ask | Writing text with `injection_detected` medium or high |
| | `ask-hidden-content-write` | ask | Writing text with `hidden_content` |

For shell commands, `target_class` is set only on paths the command writes or deletes, so `cat CLAUDE.md` is not an edit.

## Signed detector packs (SCAN-09)

Privometry's packs ship inside the binary and as a signed set: `privometry.detectorpack_set/v1` (`specs/detectorpack/v1/pack-set.schema.json`), each pack's manifest and detector files as JSON, in a DSSE envelope with payload type `application/vnd.privometry.detectorpacks+json` signed by the `release` key. `privometry definitions update` downloads `detectorpacks.json` next to the latest release, and `privometry definitions install FILE` installs one offline; both restart the daemon. `internal/definitions` uses an installed set only when:

- the signature verifies against the release keys built into the binary (none ship yet, so every set is ignored and the built-in packs run);
- its `set_version` is higher than the built-in set's (`detectorpacks.SetVersion`) and, on install, than the installed set's;
- every pack compiles and every detector passes its own samples on this engine (`content.Check`), so a pack never runs on an engine that would misread it.

A pack whose `min_sensor_version` is above the sensor's version stays at its built-in version; the rest of the set is used. Anything else keeps the whole built-in set, and `privometry definitions status` and `privometry doctor` say why. `TestBuiltInSetVersionsArePinned` fails when a built-in pack changes without a `SetVersion` bump. `scripts/sign-definitions` builds and signs the set for a release. See `docs/definitions.md`.

Community and organization packs (other publishers' keys) are P2 (EDGE-21).

## Allowlists (SCAN-09)

Policy files accept `allowlist` entries for findings people have checked, such as fake keys in test fixtures:

```yaml
allowlist:
  - detectors: [privometry/credentials:*]          # qualified IDs, or <pack>:* for a whole pack
    paths: [test/fixtures/*]                       # globs; * crosses /
    reason: Fake keys used by the parser tests
  - detectors: [privometry/credentials:aws-access-key]
    values: [AKIAIOSFODNN7EXAMPLE]                 # exact matched text
    reason: AWS's documented example key
    expires_at: 2027-06-30T00:00:00Z
```

- An entry needs `paths`, `values` or both; it never turns a detector off everywhere. With both, both must match.
- Paths match repo-relative paths for files in the repo and `~/...` for files in the home folder. They cover files at rest and file writes, never commands, URLs or MCP arguments, which have no path.
- Values match the finding's value (for credentials, the credential) or its whole match, anywhere.
- Expired entries are ignored. `privometry policy test` fails an entry naming a detector the packs in use do not have.

Allowlists filter findings before they become facts, so an allowlisted finding neither asks nor blocks and is not recorded. They apply where their policy applies: the repo policy to that repo's sessions, files and scans, the user policy (`~/.privometry/policy.yaml`) everywhere on the machine. The daemon applies them to pre-action scans, tool output and at-rest memory file scans; `privometry scan` applies them and counts what it dropped. Organization allowlists arrive with policy bundles (P2).

A repo can already loosen built-in rules through its policy's exceptions, so a repo allowlist adds no new way around protection; a change to `.privometry/policy.yaml` is flagged in merge and pull requests (`agent_file_changed`).

## Exfiltration in URLs (SCAN-13)

A markdown renderer fetches an image as soon as it shows it, so text that gets an agent to print an image whose URL carries data leaks without a click. The `privometry/injection` pack finds:

| Detector | Finds |
|---|---|
| `markdown-image-exfiltration` | An image URL with a placeholder the agent fills in: `?d=${GITHUB_TOKEN}`, `{{…}}`, `<secret>` |
| `markdown-image-encoded-data` | An image URL whose `data`, `payload`, `content`, `context`, `history` (and similar) parameter already holds at least 40 characters of base64 with high entropy |
| `markdown-link-exfiltration` | The same placeholders in a link the person is asked to click |
| `html-tag-exfiltration` | The same in an HTML `img`, `a`, `iframe`, `link`, `source`, `video` or `audio` tag |
| `embed-data-in-url` | An instruction to append, include or encode secrets, `.env`, environment variables or the conversation into a URL, link, query string or image |

They run on what agents read and load (memory files, skills, tool descriptions and output, written files), not on the agent's own commands, which the `privometry/exfiltration` rules already judge by intent. Any exfiltration finding in content an agent read marks the session, so later memory edits are denied.

## Memory file snapshots (SCAN-14)

The daemon keeps every version of a memory or instruction file it sees: the first time, after each change (by a person or an agent), and when the file is deleted. Versions live in the local timeline database (`memory_versions`, with the content stored once per digest in `memory_blobs`), never leave the machine, and are kept for 90 days and at least the last 20 per file. Files over 1 MB are hashed and scanned but not kept.

```bash
privometry memory list                              # each file: versions, last change, who, findings, changed since?
privometry memory history ~/.claude/CLAUDE.md
privometry memory diff ~/.claude/CLAUDE.md          # the previous version against the file now
privometry memory show ~/.claude/CLAUDE.md --version 12
privometry memory restore ~/.claude/CLAUDE.md --last-good
privometry memory restore ~/.claude/CLAUDE.md --version 12
```

`--last-good` picks the newest version, other than the current content, that scans clean with today's detectors and allowlists. `restore` shows the change and asks first (`--yes` skips that), keeps the current content as a version if the daemon had not seen it yet, writes the file atomically, and records a `config_change` by `person` with the version it came from. The daemon answers these commands (IPC operation `memory`), so it must be running.

## Credentials across devices (SCAN-15)

On an enrolled device the content engine keys credential fingerprints with the organization's hash key from enrollment, picked up within 10 seconds of the connected build's `privometry login` or `enroll` without a restart. The same secret then has the same fingerprint on every device of the organization. Path hashes stay on the device's own salt. Fingerprints made before enrollment, under the device's salt, are marked as such and dropped at upload. The platform groups uploaded fingerprints into credentials with the devices and people that found them and a rotation status (org-api/v1 `credentials`; privometry-platform's Findings page).

## privometry scan

`privometry scan` lists each agent's memory files (`memory_files` in the JSON report, a column in the table), including nested project files found by walking the repo (skipping `.git`, `node_modules`, `vendor`, build folders; at most 8 levels and 5,000 folders). It scans memory files, skills and agent config files, and reports `content_findings` in all three formats: a section in the table, a list in the JSON, and SARIF results with one rule per detector. Content findings count toward `--fail-on`. Credentials in config files are left to the `secret_in_config` posture check, and files read only for their MCP servers (`~/.claude.json`, which is mostly the agent's own state) are scanned only within the server entries.

On the development Mac this found 33 Claude Code memory files. The first run raised 5 findings, all false positives: skills that quote "ignore previous instructions" as an example of what to distrust, a skill telling Claude not to "tell the user to use a card", and two strings in `~/.claude.json`'s cached state. The patterns now skip quoted phrases and phrasing guidance, `~/.claude.json` is scanned only within its MCP servers, and each case is a `no_match` sample; the rerun reports none.

## Still to do

- Claude Code's `InstructionsLoaded` hook scans each loaded `CLAUDE.md` or rule file immediately, including nested files that are not discoverable from the workspace root. Unchanged files are deduplicated by content hash.
- When the daemon is unavailable, the small hook client uses the credential recognizers shared with redaction on commands, URLs, write content and MCP arguments. It applies the configured `secrets` fail mode without loading detector packs or Cedar, records credential kinds but never values, and redacts credentials before writing its temporary spool.
- Memory and instruction files are rescanned every 24 hours even when their hash is unchanged, so updated detector packs apply within a day. The persisted observation time keeps the schedule across daemon restarts.
- Snapshots start when the daemon first sees a file; earlier versions cannot be restored. Nested project files are kept only once an agent writes them or Claude Code reports loading them.
- Content agents read is scanned for injection (SCAN-12, a P2 Should) but with phrasing heuristics: security docs that discuss prompt injection without quoting it can still mark a session.
- The GitHub Action (SCAN-08) runs the same detectors on the agent files and every changed text file of a pull request; see `action/README.md`. Without a base commit (a first push, a scheduled run) only agent files are scanned.
- No release key ships yet, so signed detector pack sets are verified but never accepted.
