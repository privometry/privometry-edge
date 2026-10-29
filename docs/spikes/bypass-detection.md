# Spike: noticing when a developer turns Privometry off (EDGE-24)

> **Status (2026-10-28): phases 1 to 6 implemented**, apart from the optional organization setting for the stale threshold (`org-api/v1` draft.10, not started). Contracts: `adapter/v1` draft.7, `event-schema/v1` draft.6 (which also gives `sensor_stopped` the reasons `killed` and `stopped`), `edge-api/v1` draft.9. Answered here: the environment of a hardened-runtime binary is readable through `KERN_PROCARGS2` by the same user (macOS platform binaries such as `/bin/sleep` hide theirs); the process listing takes about 30 ms on a Mac running ~900 processes. Still open: the questions about real agents below, which need `scripts/hook-recorder` sessions. See `docs/daemon.md`.

## The problem

Privometry installs at user level: the hook goes in the agent's user settings and privometryd runs as the user. A developer owns those files and that process, so they can always turn Privometry off. On Team the goal is not to make that impossible but to make it **visible**: every route is reported to the organization as a tamper finding within minutes, with the reason when it can be known. Making it impossible needs config the developer cannot edit (managed settings deployed by an admin or MDM); that is separate work.

## What is seen today

| Route | Seen today | Gap |
|---|---|---|
| Delete or edit Privometry's hook entry | `hook_removed` / `hook_modified` within a minute; the heartbeat reports `missing` | none |
| Start the agent with a bypass flag | `hooks_bypassed` within 5 minutes | renamed binaries and wrapper scripts are not matched |
| Turn hooks off with a setting (Claude Code `disableAllHooks`, Codex `[features] hooks = false`) | user-level file: a plain `config_change`; Codex: a warning at install only | not reported as tamper; project-level files (`.claude/settings.local.json`) are not watched |
| Turn Privometry's own entry off (Antigravity `"enabled": false`) | `guard.Check` still says installed | not reported |
| Point the agent at another config folder (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`) | nothing: the daemon watches the default folders | not reported |
| Leave a Codex hook untrusted | heartbeat status `untrusted` | none |
| Auto-approve in config (`defaultMode: bypassPermissions`, `approval_policy = "never"`) | `auto_approve_mode` posture finding from scans | none |
| Stop or kill privometryd | hooks apply fail modes; heartbeats stop; `device_stale` after a day | slow, and indistinguishable from a laptop that is asleep |
| Uninstall Privometry | heartbeats stop; `device_stale` after a day | no event says it was uninstalled |
| Delete local events | `sequence_gap` | none |

## Design

Two layers. Specific checks name the reason (a setting, a folder, a flag). A generic check catches whatever they miss: **an agent that is running but whose hooks never call Privometry**. That one does not need to know how the hooks were turned off, so it also covers settings nobody has documented yet and agents patched to skip hooks.

### 1. Hook-disabling settings

- `adapter/v1` gains `hooks.disable_settings`: JSON pointers and values that turn the agent's hooks off, read in every config tier the definition lists. Claude Code: `/disableAllHooks: true`. Codex: `/features/hooks: false` and `/features/codex_hooks: false` (TOML). Gemini CLI, Copilot CLI and Cursor: left empty until confirmed on real agents (open questions below).
- `guard.Check` gains the state `disabled`: the entry is there but a setting turns hooks off, or the entry itself is off (Antigravity `"enabled": false`).
- The integrity watcher records `hooks_disabled` when a watched file turns hooks off. It also watches the project-level settings files of the projects agents run in: the working folders of sessions seen in hook calls, and of running agent processes (section 2).
- The heartbeat reports `disabled` for the install tiers, so the platform's finding resolves itself when hooks are turned back on, as `missing` does now.

### 2. Silent agents (the backstop)

- **Process model.** `platform.ProcessArgs` becomes `platform.Processes`: PID, parent PID, start time and arguments, plus the working folder on macOS and Linux. Linux reads `/proc`; macOS `sysctl kern.proc.all` with `KERN_PROCARGS2` for arguments (first `ps`, replaced as too slow) and `lsof` for working folders; Windows `Win32_Process` (`ProcessId`, `ParentProcessId`, `CreationDate`, `CommandLine`).
- **Who called.** `privometry-hook` adds its parent PID to the IPC request (free to read). The daemon walks up from it to the agent process (the hook usually runs under a shell the agent started) with per-process reads, cached by PID and start time: `/proc/<pid>/stat` on Linux, `sysctl kern.proc.pid` on macOS, a Toolhelp snapshot on Windows only when a PID is not cached. The hook client stays as small and fast as it is.
- **The check**, every minute: an agent CLI process (matched as for bypass flags) that has run for 3 minutes, whose definition has a `session_start` event, whose session files (`detect.session_paths`, its transcripts) have changed since it started, at least a minute ago, and from which no hook call has come, gets one `hooks_silent` event. The session files keep idle sessions out: agy and Codex fire their session-start hook only at the first prompt. Its reason is filled from sections 1 and 3 when one applies (`setting`, `config_dir_override`, `untrusted_hook`), else `unknown`.
- **False positives.** Long-running commands that start no session (`claude mcp serve`, `codex mcp-server`) are listed per agent in `detect.no_session_args`. Desktop apps (Antigravity.app, the Cursor IDE) are left out: they run all day without sessions. Cursor has no session-start event, so its CLI is left out until a reliable signal is found. With reason `unknown` the finding is medium and says so; with a known reason it is high.

### 3. Config-folder overrides

- For a silent agent, the daemon reads only the variables in its definition's `env_overrides` from the process's environment: `/proc/<pid>/environ` on Linux, `sysctl KERN_PROCARGS2` on macOS (allowed for the user's own processes). Nothing else from the environment is read or kept, and the path goes through path redaction.
- When the override names a folder whose config has no Privometry hook, the reason is `config_dir_override`. If that folder does have the hook (a person installed it there), the agent is not silent anyway.
- Windows: reading another process's environment means reading its memory, so it is not done; the reason stays `unknown` there.

### 4. Agents under other names

- `detect.process_patterns`: path fragments that identify an agent whatever the program is called, matched against the program and, for script runtimes, the script: `@anthropic-ai/claude-code/`, the native installer's `claude/versions/`, `@openai/codex/`, `@google/gemini-cli/`, `@github/copilot/`. Used by bypass flags, silent agents and discovery.
- A native binary copied to an unrelated folder under another name is still not recognized. If its hooks run, its calls show as an unknown parent and are recorded as such; if they do not, nothing on the device can tell it is an agent.

### 5. Sensor stopped, killed or uninstalled

- privometryd writes `alive_at` to its data folder every minute and a stop marker with the reason on a graceful stop.
- At start it compares the previous run with the system's boot time (`kern.boottime`, `/proc/stat btime`, `GetTickCount64`). Stopped by a shutdown or reboot: nothing to report. Otherwise, if it was down for more than 5 minutes: a `sensor_stopped` event with how long it was down, whether it was killed (no marker) or stopped (marker), and how many decisions the hook client made with fail modes in that time (counted when the spool is imported). That last number is the evidence that agents were used while it was off.
- `privometry daemon uninstall` and `guard uninstall` record `sensor_uninstalled` and `hook_removed` (`changed_by: person`, through the CLI) and wait up to 5 seconds for the upload before stopping. Deleting the files by hand skips this; the platform then relies on `device_stale`.
- launchd and systemd restart a killed daemon within seconds, so a lasting stop means unloading the service, which is a graceful stop the developer must keep up across logins.

### 6. Platform

- `Ingest.tamper`: `hooks_disabled` high; `hooks_silent` high with a known reason, medium with `unknown`; `sensor_stopped` medium, high when actions ran while it was down; `sensor_uninstalled` high. All stay open when a heartbeat later reports the hook installed (the keep set in `Heartbeats`).
- Heartbeat status `disabled` raises `hook_disabled` and resolves like `hook_missing`.
- `device_stale` stays at a day by default (laptops sleep), and becomes an organization setting for teams that want it shorter.
- The console's findings list shows the reason and the down time; webhooks need nothing new (`finding.opened`).

## Contract changes

| Contract | Change |
|---|---|
| `adapter/v1` draft.7 | `hooks.disable_settings`, `detect.process_patterns`, `detect.no_session_args` |
| `adapter/v1` draft.8 | `detect.session_paths`, so idle sessions of agents with a lazy session-start hook are not silent |
| `event-schema/v1` draft.6 | integrity checks `hooks_disabled`, `hooks_silent`, `sensor_stopped`, `sensor_uninstalled`; `integrity.reason` (`setting`, `config_dir_override`, `untrusted_hook`, `unknown`); `integrity.down_seconds`, `integrity.actions_while_down` |
| `edge-api/v1` draft.9 | heartbeat hook status `disabled` |
| `org-api/v1` draft.10 | organization setting for the stale threshold (phase 6, optional) |

## Phases

| # | Work | Days |
|---|---|---|
| 1 | Contracts and definitions: the fields above, Claude Code and Codex disable settings, process patterns, no-session arguments | 1 |
| 2 | Hook-disabling settings: `guard.Check` state `disabled` (including Antigravity's entry), the watcher over settings tiers and project files, heartbeat status | 2 |
| 3 | Process model on three OSes, parent PID in the hook request, the daemon's ancestry cache and last call per agent process | 2–3 |
| 4 | Silent agents with reasons, environment overrides on macOS and Linux, process patterns (also used by bypass flags) | 2–3 |
| 5 | Sensor lifecycle: alive time, stop marker, boot time, actions while down, uninstall events | 2 |
| 6 | Platform: severities, keep set, `hook_disabled`, console text, optional stale setting | 1–2 |
| 7 | Docs, and confirming the open questions on real agents with `scripts/hook-recorder` | 1 |

About two weeks for one engineer. Phases 2 and 5 can go first: phase 2 watches the projects seen in hook calls, and adds those of running agents once phase 3 lands.

Tests, as for the existing checks: injected process lists, parent chains and environments; a fake clock for the 3-minute window and the down time; `guard` states per agent; platform API tests for findings raised, kept and resolved. Nothing needs the live control plane.

## Open questions (to confirm on real agents)

- [x] Does each agent fire its session-start hook when it starts, or only at the first prompt? Checked on macOS, 2026-10-29, by starting each agent idle in a trusted project with the recorder registered and waiting 20 seconds without a prompt:
  - **agy 1.4.10: at the first prompt.** Signed in, at its ready prompt, no `SessionStart`; in the recorded session it came in the same second as the first `PreInvocation`.
  - **Codex 0.165.0: at the first prompt.** At its ready prompt, project and `session_start` hook trusted, no `SessionStart`, although the app server starts its thread at launch.
  - Copilot CLI: not settled; it stopped at its folder-trust dialog. Cursor 3.27.22 sent `sessionStart` with the first prompt.
  - **Claude Code 2.1.302: at launch** (`source: startup`), checked in a trusted folder with the hook passed through `--settings`.
  - **Consequence, fixed:** the silent check reported an agy or Codex session left open for 3 minutes without a prompt as `hooks_silent`. No agent wrote a transcript while idle; all did as soon as they were used (Copilot creates its session folder at launch, but `events.jsonl` only once used). `adapter/v1` draft.8 adds `detect.session_paths`, and the check now waits until one of those files has changed since the process started, plus a minute for the first hook call. The files belong to the agent, not the process: a second session of the same agent makes an idle one count as in use.
- [ ] Which settings turn hooks off in Gemini CLI, Copilot CLI and Cursor?
- [ ] Does Claude Code's `disableAllHooks` in user settings also turn off hooks from managed settings? (It decides how much the managed install protects.)
- [x] Can `KERN_PROCARGS2` read the environment of notarized agent binaries under the hardened runtime, for the same user? Yes, on macOS for `claude` 2.1.302, `codex` 0.165.0, `agy` 1.4.10 and `copilot` 1.0.105, all signed with the hardened runtime (`flags=0x10000(runtime)`). Codex refuses to start when `CODEX_HOME` names a folder that does not exist, so an override always names a real one.
- [x] How much does the process listing cost each minute on a busy machine (target: under 50 ms)? With `ps`, 31 to 49 ms for about 750 processes on an M4 Pro, most of it `ps` reading every command line. The macOS listing now reads the process table with `sysctl kern.proc.all` and each command line with `KERN_PROCARGS2`, as `ps` does: 5 to 7 ms, with exact arguments instead of a split command line.

## What this cannot catch

- A local administrator or root: they can change the daemon itself.
- Agents in a container, VM or WSL where privometryd does not run, and cloud agents (Claude Code on the web, Codex cloud, the Copilot coding agent): they never run on the device.
- A renamed copy of a native agent binary with hooks off (section 4).
- A developer who unloads the service and never logs in again is seen only as `device_stale`.

Preventing these, rather than reporting them, needs managed installs (admin-owned settings with `allowManagedHooksOnly` for Claude Code, Copilot's policy folder), deployed and restored by MDM, and network controls for cloud agents.
