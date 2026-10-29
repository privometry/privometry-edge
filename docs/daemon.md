# Daemon, hook client and guard

How a tool call is decided on the developer's machine.

```
agent ──stdin──► privometry-hook ──Unix socket or named pipe──► privometryd ──► policy ──► timeline (SQLite)
                     │  (daemon down or slow)
                     └──► fail modes alone ──► spool.jsonl ──(imported later)──► timeline
```

## privometryd

The daemon (`cmd/privometryd`, `internal/daemon`). Install it as a per-user background service with `privometry daemon install`, or run `privometryd` in the foreground. Timeline targets are redacted at the SQLite persistence boundary by default, including events imported from the fallback spool.

- **Socket**: `~/.privometry/privometryd.sock`, mode 0600 in a 0700 folder. One JSON request and response per connection (`internal/ipc`). A lock file (`privometryd.lock`) keeps it to one daemon per data folder.
- **Windows**: a named pipe, `\\.\pipe\privometry-<user>` (with `PRIVOMETRY_HOME` set, the name also carries a hash of that folder). Its access list admits only the user, it refuses remote clients, and clients check that the pipe is owned by the user (or SYSTEM or Administrators) before sending anything, so another account cannot stand up a pipe of the same name. The data folder is `%LOCALAPPDATA%\Privometry`; "private" there means an access list granting only the user, SYSTEM and Administrators, and a folder that grants anyone else access is tightened if the user owns it, or refused. Keys are sealed with DPAPI under the user's logon (`keystore` kind `windows-dpapi`).
- **Per hook call**: reads the payload through the adapter's request pointers, maps the tool to an action (`tool_kinds`, `tool_targets`, MCP name template, `apply_patch` files), looks up the session, decides with the merged policy (shipped packs, `~/.privometry/policy.yaml`, the repo's `.privometry/policy.yaml`), renders the agent's native reply from the adapter's templates, and records the event.
- **Workspace**: the git root, or the working folder when it is inside home and not under git, so a project folder's own files are not treated as "home".
- **Policies** are cached per repo and reloaded when either policy file changes, or when an exception expires.
- **Verdicts the agent cannot express** use the event's fallback (Codex has no ask: it receives deny); the event records `native_verdict`.
- **Dedupe**: a tool call reported twice (Cursor also runs Claude Code's hooks) is decided once, by `tool_use_id`, for two minutes. The caller is detected from payload markers, so Cursor's calls are recorded as Cursor.
- **Session state**: post-tool hooks mark a session as having seen untrusted input after web fetches and searches, MCP responses, `curl`/`wget`, and `gh issue`/`pr` reads. The flag feeds `untrusted_input_seen` in every later decision and survives daemon restarts. MCP results from a server that a user or organization policy rule explicitly allows (for example the Claude desktop app's own `ccd_*` tools) do not set the flag; a repo policy cannot vouch for servers this way. Their output is still scanned, so injected instructions in it still mark the session.
- **Housekeeping**: imports the hook client's spool every minute; prunes events after 30 days and idle sessions after 7.
- **Imported hooks**: Cursor also runs Claude Code's hooks. When Cursor has its own Privometry hook, the imported Claude Code call gives no opinion and is not recorded, so each action is decided once.
- **Status**: `privometry daemon status` (and `guard status`) ask the daemon for its version, uptime and the last hook call per agent. The daemon also lists the IPC operations it answers, so a CLI newer than the running daemon says to restart it.
- **MCP shim**: `privometry-mcp-shim` asks the daemon about MCP tool calls, results and tool lists through the `mcp` operation; see `docs/mcp-shim.md`.
- **Integrity**: every minute it hashes the agents' config files and records config changes and removed or modified Privometry hooks; see `docs/developer-experience.md`.
- **Bypass flags**: every five minutes it lists running processes and records a `hooks_bypassed` integrity event when an agent runs with one of its definition's `detect.bypass_flags` (`--dangerously-skip-permissions`, `--yolo`, `--approval-mode yolo` and so on), once per agent and flag while it keeps running. Agents are found by binary name or, whatever the program is called, by `detect.process_patterns` (`@anthropic-ai/claude-code/`, the native installer's `claude/versions/`). Antigravity's flag turns its hooks off, so Privometry sees nothing that session does; the others skip permission prompts while hooks still run. Command lines are read in memory and dropped; the event names only the agent and the flag. The control plane raises a high tamper finding that an installed-hook heartbeat does not clear.
- **Hooks turned off** (`docs/spikes/bypass-detection.md`): a setting from the definition's `hooks.disable_settings` (Claude Code `disableAllHooks: true`, Codex `[features] hooks = false`) in a user, managed or project settings file, or Antigravity's `"enabled": false` on Privometry's own entry, makes `guard status` say `disabled` and the heartbeat report `disabled`, and records `hooks_disabled` once when a file starts holding it. Project files are watched for the workspaces agents worked in recently (`.claude/settings.local.json`).
- **Silent agents**: `privometry-hook` sends its parent PID; the daemon walks up from it (`/proc/<pid>/stat`, `sysctl kern.proc.pid`, a Toolhelp snapshot) and remembers every process above a hook call. Every minute, an agent CLI that has run for three minutes, has a session-start hook, has been in use for a minute (one of its transcripts, `detect.session_paths`, changed after it started: agy and Codex call no hook until the first prompt), and has not called is reported once as `hooks_silent` with a reason: `config_dir_override` (its `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `COPILOT_HOME` names a folder without Privometry's hook; only those variables are read from its environment, on macOS and Linux), `setting`, `untrusted_hook` (Codex) or `unknown`. Agents whose hook is not installed, desktop apps, `detect.no_session_args` commands (`claude mcp serve`, `codex app-server`), agents run with a bypass flag, and Cursor are left out.
- **Sensor stopped or uninstalled**: privometryd writes `alive.json` every minute and `stopped.json` on a graceful stop. At start, a previous run that ended more than five minutes ago, after the last boot, records `sensor_stopped` with the down time, `killed` or `stopped`, and how many decisions the hook client spooled meanwhile. `privometry daemon uninstall` and `guard uninstall` tell the daemon first (IPC operation `lifecycle`), which records `sensor_uninstalled` or `hook_removed` and waits up to five seconds to upload it.
- **Probes**: `privometry doctor` gets a one-time token (`probe` operation) so its test hook call is decided but not recorded.
- **Content scanning**: commands, URLs, MCP arguments and written content are scanned before each decision (5 ms budget), tool output after it; findings become `content_finding` events and facts for the rules, and memory files are hashed with person-or-agent attribution. See `docs/content-scanning.md`.
- **Data**: `~/.privometry/` (or `$PRIVOMETRY_HOME`, or `%LOCALAPPDATA%\Privometry` on Windows): `privometry.db`, `failmodes.json`, `spool.jsonl`, `alive.json`, `stopped.json`, `privometryd.log`, all 0600.
- **Flags**: `-log <file>` appends the log to a file (the Windows build has no console), `-home <dir>` sets the data folder as `PRIVOMETRY_HOME` does, `-supervise` runs privometryd as a child and starts it again whenever it stops (after 1 second, doubling to a minute while it keeps stopping soon after it starts); it holds `privometryd-supervisor.lock`.

## privometry daemon

```bash
privometry daemon install --dry-run   # show the service file and commands
privometry daemon install             # write it, load it, wait for privometryd to answer
privometry daemon status              # service state, daemon version and uptime, last hook call per agent
privometry daemon restart
privometry daemon uninstall
```

| OS | Service | File |
|---|---|---|
| macOS | launchd agent `dev.privometry.privometryd` (`launchctl bootstrap gui/<uid>`), `RunAtLoad`, `KeepAlive`, log in `~/.privometry/privometryd.log` | `~/Library/LaunchAgents/dev.privometry.privometryd.plist` |
| Linux | systemd user unit, `Restart=on-failure`, enabled for login | `~/.config/systemd/user/privometryd.service` (honors `XDG_CONFIG_HOME`) |
| Windows | Task Scheduler task `\Privometry\privometryd`: starts at the user's logon in their session with normal rights (`InteractiveToken`, `LeastPrivilege`), no time limit, restarted every minute if it stops; `schtasks /Create /XML`, `/End`, `/Run`; state from `Get-ScheduledTask` | `%LOCALAPPDATA%\Privometry\privometryd-task.xml` (UTF-16) |

The service runs as the user, never root or an administrator. `PRIVOMETRY_HOME` is carried into the service when set (on Windows as `-home`, since a task has no environment of its own). Installing again rewrites the file and restarts the daemon, which is how upgrades work; `status` flags a service file that no longer matches.

On Windows the PRD's "Windows service" is a logon task rather than a Service Control Manager service: a service runs outside the user's session, needs an administrator to install, and could not open the user's DPAPI-sealed keys. `privometryd.exe` is built for the GUI subsystem so the task opens no console window, and logs with `-log`.

Some policies stop standard users from creating scheduled tasks. When `schtasks /Create` fails, `install` sets `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `Privometry` to `privometryd -supervise -log …` instead, starts it at once, writes the command line to `%LOCALAPPDATA%\Privometry\privometryd-run.txt`, and says so. `status` and `doctor` then report the Run key; `restart` ends the supervisor and its daemon (`taskkill /T` filtered by PID and image name) and starts it again; installing once the task is allowed moves to the task and removes the value; `uninstall` removes both.

## Timeline

`internal/timeline`, SQLite in WAL mode (`modernc.org/sqlite`, no cgo). Tables follow the database design: `events` (one row per event, the full `privometry.event/v1` payload with the target redacted, plus `target_clear`, which never leaves the device), `sessions`, and `state` (device ID, `device_seq`). `device_seq` is incremented in the same transaction as the insert, so the sequence has no gaps. Every stored event validates against the event schema in tests.

## privometry-hook

The client agents run (`cmd/privometry-hook`, `internal/hookclient`): `privometry-hook <agent> <event>`, payload on stdin.

- Sends the call to the daemon with a 200 ms budget (`PRIVOMETRY_HOOK_TIMEOUT_MS`) and prints its reply.
- If the daemon is down, slow or fails, it decides alone: extracts facts with the same extractors, maps each request to a category, and applies the fail mode from `failmodes.json` (written by the daemon) or the confirmed P1 defaults: catastrophic **closed** (deny), secrets and exfiltration **ask** (deny where the agent cannot ask), everything else **open**. The daemon, hook client, and doctor share one canonical definition of these defaults.
- **Open never auto-approves**: it prints nothing, so the agent's own permission prompt still applies.
- Each fallback decision is appended to `spool.jsonl` (capped at 10 MB) as a `fail_mode` event.
- Its fallback replies are built in and tested against the adapter templates, so they cannot drift.
- It loads no policy engine, database, YAML or schema code: 3.5 MB.

## privometry guard

```bash
privometry guard install --dry-run      # show the change to ~/.claude/settings.json
privometry guard install                # register privometry-hook for every hook event
privometry guard status                 # installed, partial, stale or missing, per agent
privometry guard uninstall              # remove only Privometry's entries
```

- Edits the settings file as ordered JSON, so the user's keys stay in place and their own hooks are untouched; installing twice changes nothing.
- Keeps a copy at `settings.json.privometry-backup` before the first change and writes atomically with the same permissions. Refuses to touch a file that is not valid JSON.
- Adds `onFailure: block` to decision hooks only when the detected Claude Code version supports it (2.1.295 and later); older or unknown versions might reject the key.
- On Windows the hook path is always written in double quotes, which both cmd.exe and Git Bash accept.
- Honors `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.

| Agent | File | Fail closed | Notes |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json` | `onFailure: block` on `PreToolUse`, version 2.1.295 and later | |
| Cursor | `~/.cursor/hooks.json` | `failClosed: true` on decision events | Shell and MCP events can ask; `preToolUse` covers writes, deletes and subagents |
| Gemini CLI | `~/.gemini/settings.json` | Not available: a crash, timeout or non-JSON output lets the action proceed | `BeforeTool` cannot ask: asks are denied with the reason. Timeouts are written in milliseconds |
| Antigravity | `~/.gemini/config/hooks.json`, shared by the agy CLI, desktop app and IDE; Privometry's entries sit under the hook name `privometry` | Built in, as reported from testing: a `PreToolUse` hook that crashes, times out or exits non-zero blocks the call | Asks are sent as `force_ask`, because `ask` would skip the prompt after an earlier "Always Allow". `--dangerously-skip-permissions` turns hooks off. Workspace hooks (`.agents/hooks.json`) load only in trusted folders |
| Copilot CLI | `~/.copilot/hooks/privometry.json` (honors `COPILOT_HOME`), a file of its own that `uninstall` deletes | Built in: a crashing `preToolUse` hook denies the call; a timeout lets it proceed | The command goes in `bash` (`powershell` with `& "…"` on Windows) |
| Codex CLI | `~/.codex/hooks.json` | Not available: if `privometry-hook` crashes, the action proceeds | `UserPromptSubmit` records privacy-preserving query metadata; `PreToolUse` guards actions. Codex runs a new user hook only after you trust it: open Codex and run `/hooks` once. `install` prints this step and warns if `[features] hooks = false` in `config.toml` |

After upgrading from a version that only registered tool hooks, run `privometry guard install --agent codex_cli` again and approve the updated hook set through Codex `/hooks`. Query events store a device-keyed fingerprint, prompt identifier and character count. The raw query text is never written to the timeline event database.

`guard status` shows each agent's state and its last hook call from the daemon. A Codex hook that is installed but has never fired shows "no calls yet: Open Codex, run /hooks and trust the Privometry hook once".

## Measured

On an M-series Mac, spawning `privometry-hook` from a script:

| Path | p50 | p95 |
|---|---|---|
| Daemon running (`ls`, `rm -rf ~`, a `bash -c` pipeline) | 4.1–4.4 ms | 5.3–8.4 ms |
| Daemon down (fail modes alone) | 3.8 ms | 5.3 ms |

The decision inside the daemon takes under 1 ms. Verified end to end with a real Claude Code 2.1.304 session: `ls` and a repo-local write were auto-approved without `--allowedTools`, `rm -rf ~/…` was denied by `home-recursive-delete`, `cat .env` was stopped by `read-env-file`, and with the daemon stopped the same `rm` was denied by the hook client's closed fail mode and recorded once the daemon came back.

## Known gaps

- Privometry cannot read Codex's hook trust state; it infers it from whether Codex has called the hook yet.
- `guard` rewrites the settings file in two-space JSON. Content is preserved, but a file formatted differently (inline arrays, tabs) is reformatted; `--dry-run` shows exactly what changes.
- Cursor, Gemini CLI, Copilot CLI and Antigravity installs are tested against their documented formats, not yet against recorded sessions (`test/fixtures/<agent>/documented`). Codex is verified against sessions recorded with 0.164.0.
- Gemini CLI and Antigravity run hooks with a trimmed environment. When `HOME` is missing, `privometry-hook` takes the home folder from the account database (and on Windows derives `LOCALAPPDATA` and `USERNAME`); a missing `PRIVOMETRY_HOME` cannot be recovered, so side-by-side installs need it allowed. Not verified with either agent yet.
- The launchd agent is verified on a real Mac; the systemd unit, the Windows task and the Run key fallback are tested with a fake runner only.
- Bypass flags are found by process name, process patterns and arguments: a native agent binary copied elsewhere under another name, or whose flags come from its settings file rather than its command line, is not noticed. A silent agent is the backstop for the second case, not the first.
- Silent-agent reasons on Windows stay `unknown` for config-folder overrides: reading another process's environment there means reading its memory. Linux process reads are covered by CI only; the macOS reads are verified locally (the environments of `claude`, `codex`, `agy` and `copilot`, all hardened-runtime binaries, are readable by the same user; the `sysctl` listing takes 5 to 7 ms for ~750 processes, against 31 to 49 ms with `ps`; one `kern.proc.pid` read takes about 10 µs). agy and Codex fire their session-start hook only at the first prompt, so the silent check counts an agent only once its transcripts (`detect.session_paths`) changed after it started.
- `disable_settings` for Gemini CLI, Copilot CLI and Cursor are not known yet, and whether each agent fires its session-start hook at start rather than at the first prompt is not yet confirmed on real sessions.
- The Windows transport, access-list checks, DPAPI store and lock have tests that run only on Windows (the `test-windows` CI jobs); they are compiled and vetted from macOS but have not yet run on a Windows machine, and neither has `schtasks` registering the logon task as a standard user.
- MCP calls whose tool name does not look read-only are medium risk, so they ask under `unmatched: auto`. That includes host apps' own MCP tools (the Claude desktop app's `ccd_*` tools); allow the ones you trust in `~/.privometry/policy.yaml`.
- The fail modes file reflects the user and built-in layers only; a repo policy's stricter fail modes apply only while the daemon runs.
- Reading repo files does not mark a session untrusted, so issue text pasted into a repo file is not tracked.
- The 200 ms hook budget is above the contract's proposed 100 ms, because the first call for a new repo compiles its policy.
