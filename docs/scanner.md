# privometry scan

Finds coding agents, their running processes, config files, MCP servers, hooks, skills and installed plugins, and flags risky settings. It only reads: no file is changed. Process enumeration and each agent's version command have a 3-second timeout.

```bash
privometry scan                                   # this machine, plus the git repo you are in
privometry scan --repo ../api                     # this machine plus another repo
privometry scan --no-machine --format sarif --fail-on high   # CI: repo only
git diff --name-status --no-renames origin/main...HEAD | privometry scan --no-machine --changed - --fail-on high   # a merge or pull request
```

| Flag | Meaning |
|---|---|
| `--format` | `table` (default), `json` or `sarif` |
| `--repo DIR` | Repo whose project config to scan; default is the git repo containing the current directory |
| `--no-repo` | Scan no repo |
| `--no-machine` | Skip user and managed config and installed-agent detection |
| `--fail-on SEVERITY` | Exit 1 if any finding is `low`, `medium`, `high` or `critical` or above |
| `--output FILE` | Write the report to a file |
| `--changed FILE` | Files a merge or pull request changes, as `git diff --name-status` output or one path per line (`-` reads stdin). Changed agent files become `agent_file_changed` findings, and every changed text file is scanned with the detectors that apply to repositories |

Exit codes: 0 success, 1 a finding at or above `--fail-on`, 2 usage or runtime error.

## What it reads

Everything comes from the adapter definitions (Claude Code, Cursor, Codex CLI, Gemini CLI, Copilot CLI, Antigravity): the ones in `adapter-defs/`, or a newer signed set installed with `privometry definitions` (see `docs/definitions.md`): binaries, process names and app bundles to detect, config files per tier (user, project, managed) and OS, MCP server locations, and which posture checks apply. Process detection compares executable names only; command lines and PIDs are never retained. Formats: JSON, JSON with comments, TOML, YAML, and frontmatter in `SKILL.md` and `.mdc` files. Desktop apps that ship an agent's engine are found by that binary: the Codex desktop app is the engine inside `/Applications/ChatGPT.app`, which also answers the version check when the `codex` on PATH is missing or broken. Claude Code's installed-plugin registry contributes plugin ID, marketplace, version and scope; installation paths are discarded. It also lists each agent's memory and instruction files (`memory_files`: `CLAUDE.md`, `AGENTS.md`, rules folders, automatic memory), including nested ones in the repo.

## Checks

| Check | Severity | Fires when |
|---|---|---|
| `writable_managed_config` | critical | A managed config file or its directory is writable by other users |
| `auto_approve_mode` | high | Claude Code `bypassPermissions` or `Bash(*)`; Cursor `Shell(*)`; Codex `approval_policy = "never"` (also in profiles); Gemini CLI `tools.allowed` holding `run_shell_command`; Antigravity `permissions.allow` holding `command(*)` |
| `sandbox_disabled` | high | Codex `sandbox_mode = "danger-full-access"` |
| `secret_in_config` | high | A config value matches a known token format, or a credential-named key holds a literal |
| `project_hook` | medium | The repo registers a hook (other than Privometry's) |
| `project_mcp_server` | medium | The repo declares an MCP server |
| `unpinned_mcp_server` | low | An MCP server launches a package with no fixed version (`npx`, `uvx`, `bunx`, `pnpm dlx`, `pipx run`, `docker run`) |
| `managed_hooks_only_off` | low | Claude Code managed settings exist without `allowManagedHooksOnly` |
| `agent_file_changed` | medium or low | With `--changed`: a project-tier file an agent reads was added, edited or deleted. Config holding hooks, permissions, settings, plugins or MCP servers, MCP declarations, and `.privometry/policy.yaml` are medium; instructions, rules and skills are low. Nested instruction files (`docs/AGENTS.md`) count |

## Content findings

Memory files, skills and agent config files are also scanned with the detector packs in use for credentials, injected and safety-weakening instructions, and hidden content. With `--changed`, so is every changed text file in the repo (source `repo`; binary files, symlinks and files over 1 MB are skipped or truncated). Hits are reported as `content_findings` (a table section, a JSON list, and SARIF results with one rule per detector) and count toward `--fail-on`. See `docs/content-scanning.md`.

Allowlist entries in the policy files that cover the scan drop accepted findings, such as fake keys in test fixtures: the repo policy for a repo scan, and also the user policy (`~/.privometry/policy.yaml`) for a machine scan. The report counts them (`allowlisted` in JSON, a line in the table). A policy file that fails to load is reported on stderr and its allowlist is not used.

## Privacy

Reports never contain secret values. Commands and URLs pass through the same redaction as uploaded events; MCP `env` and header values are dropped and only their names kept; secret findings name the file and JSON pointer, not the value. Paths under your home directory are shown with `~`, and repo paths relative to the repo. A test renders every format against a fixture full of fake secrets and fails if any leaks.

## Output formats

- **table**: agents, MCP servers, hooks, unreadable files, then findings with file, line and a fix.
- **json**: `privometry.scan/v0`. The shape may still change before it gets its own spec; the GitHub Action reads `findings`, `content_findings` and `allowlisted`.
- **sarif**: SARIF 2.1.0 with one rule per check and `security-severity` scores. Repo findings use paths relative to `%SRCROOT%` and a line number, so GitHub code scanning can annotate them.

## Known gaps

- Cursor's IDE auto-run setting lives in the app's state database; only `~/.cursor/cli-config.json` is checked.
- The Cursor, Gemini CLI, Copilot CLI and Antigravity definitions are based on documentation; Claude Code and Codex are verified against recorded fixtures. Copilot CLI permissions are command-line flags, so it has no `auto_approve_mode` check.
- Windows paths are defined and tested with a simulated Windows environment, not yet on a Windows machine. The "writable system config directory" check reads access lists on Windows (writes granted to anyone but the owner, SYSTEM, Administrators and TrustedInstaller).
- SARIF output is checked structurally, not against the official SARIF schema.
- Without `--changed`, only agent files are content-scanned, not the rest of the repo.
