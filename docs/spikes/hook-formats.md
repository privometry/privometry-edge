# Spike: agent hook formats (M0)

Date: 2026-10-23. Goal: confirm how each P1 agent lets Privometry intercept a tool call before it runs, and what that means for the adapter definitions and the hook client.

## Status

| Agent | Pre-tool hook | Evidence | Fixtures |
|---|---|---|---|
| Claude Code 2.1.304 | `PreToolUse`, full allow / ask / deny | Recorded from a real headless session | `test/fixtures/claude_code/2.1.304/hooks/` (14 payloads) |
| Cursor | `preToolUse` plus `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` | Official docs only | Pending: needs a run in the Cursor IDE |
| Codex CLI 0.164.0 | `PreToolUse`, allow / deny only | Recorded from real `codex exec` sessions | `test/fixtures/codex_cli/0.164.0/hooks/` (14 payloads) |

Sources: [Claude Code hooks](https://code.claude.com/docs/en/hooks.md), [Claude Code settings](https://code.claude.com/docs/en/settings.md), [Cursor hooks](https://cursor.com/docs/hooks.md), [Cursor third-party hooks](https://cursor.com/docs/reference/third-party-hooks.md), [Codex hooks](https://developers.openai.com/codex/hooks.md), [Codex managed configuration](https://developers.openai.com/codex/enterprise/managed-configuration.md).

## Comparison

| | Claude Code | Cursor | Codex CLI |
|---|---|---|---|
| Hook file, user tier | `~/.claude/settings.json` | `~/.cursor/hooks.json` | `~/.codex/hooks.json` or `[hooks]` in `config.toml` |
| Project tier | `.claude/settings.json`, `.claude/settings.local.json` | `.cursor/hooks.json` | `.codex/hooks.json` (trusted projects only) |
| Managed tier | `managed-settings.json` (+ `managed-settings.d/`), MDM plist or registry | `/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json` | `requirements.toml` (`/etc/codex/`, `%ProgramData%\OpenAI\Codex\`, MDM key) |
| Relocation env var | `CLAUDE_CONFIG_DIR` | none documented | `CODEX_HOME` |
| Decision output | `hookSpecificOutput.permissionDecision` + `permissionDecisionReason` | `permission` + `user_message` + `agent_message` | same as Claude Code |
| `ask` from pre-tool | Yes | Only on `beforeShellExecution` and `beforeMCPExecution` | No: an `ask` marks the hook failed and the call proceeds |
| Default on hook failure | Open | Open (bad JSON on permission hooks fails closed) | Open |
| Fail-closed switch | `"onFailure": "block"` (v2.1.295+) | `"failClosed": true` | None |
| Shell tool name | `Bash` (also `PowerShell`) | `Shell` | `Bash` |
| File tools | `Read`, `Write`, `Edit` | `Read`, `Write`, `Delete` | `apply_patch` (also matches `Edit`, `Write`) |
| MCP tool name | `mcp__<server>__<tool>`, plus `mcp_server.source` (v2.1.274+) | `MCP:<tool>` with `mcp_server_name` | `mcp__<server>__<tool>` |
| Config-change event | `ConfigChange` (settings and skills) | None | None |
| Managed-only lock | `allowManagedHooksOnly` | Not found | `allow_managed_hooks_only` |

## What the recordings showed (Claude Code)

- The `PreToolUse` payload matches the docs: `session_id`, `transcript_path`, `cwd`, `prompt_id`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`.
- There is one undocumented field, `effort: {"level": ...}`. Parsers must ignore unknown fields.
- `tool_input.file_path` is absolute for `Read`, `Write` and `Edit`. `Bash` carries `command` and `description`.
- `PermissionRequest` fired for `rm -rf ./out.txt` after `PreToolUse` returned nothing, so it is a usable second checkpoint.
- `ConfigChange` fired with `source: "skills"` when a synced skill changed mid-session. Claude Code reports config drift itself.
- No MCP call was recorded. That needs a run with a local MCP server.

## What the recordings showed (Codex CLI 0.164.0)

- Hook events in this version: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PermissionRequest`, `Stop`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `PreCompact`, `PostCompact`. Hooks are on by default (feature `hooks`, stable).
- Every payload has `session_id`, `transcript_path` (null under `codex exec --ephemeral`), `cwd`, `hook_event_name`, `model` and `permission_mode`. `codex exec` reports `bypassPermissions` whatever the sandbox and approval policy.
- `UserPromptSubmit` and tool events carry `turn_id`; there is no `prompt_id`.
- `PreToolUse` and `PostToolUse` carry `tool_name`, `tool_input` and `tool_use_id` (`exec-<uuid>`). Shell is `Bash` with `tool_input.command`. File edits are `apply_patch` with the whole patch in `tool_input.command` (`*** Update File:`, `*** Add File:`, `*** Delete File:`). MCP tools are `mcp__<server>__<tool>` with the tool's arguments as `tool_input`.
- `PostToolUse` fires only after a tool succeeds. `tool_response` is text for `Bash` and `apply_patch` and the MCP result object for MCP tools. A command the sandbox refused had no `PostToolUse`.
- `SessionEnd` carries `reason` and no `model`. Codex caps its timeout at 3 seconds and warns on every run when a hook asks for more.
- `PermissionRequest` did not fire under `codex exec`, which never offers escalation; it needs an interactive session with on-request approvals.
- Trust: `codex` lists new or changed hooks at startup ("Trust all and continue"), and `/hooks` reviews them. Trust is saved per hook in `config.toml` as `[hooks.state."<hooks.json path>:<event>:<group>:<hook>"]` with a `trusted_hash`; changing a hook's command or timeout needs trust again. `codex exec --dangerously-bypass-hook-trust` skips this for one run.
- End to end (0.164.0, `privometry guard install`, trusted once): Codex runs `privometry-hook` on all five registered events, honors the `hookSpecificOutput` deny (the model reported the command "blocked by a PreToolUse hook" with Privometry's reason), and shows no timeout warning with `SessionEnd` registered at 3 seconds. The timeline shows the policy verdict (`ASKED` for `cat .env`) while Codex received a deny.
- A model can misread a prompt into a dangerous command: asked to run "rm -rf build ." as a sentence, it ran `rm -rf build .`. The read-only sandbox stopped it; the payload is kept as a fixture.

## What the recordings showed (Codex CLI 0.165.0)

Recorded 2026-10-29 in an interactive session with `--sandbox workspace-write --ask-for-approval on-request`, with the recorder also registered for `PermissionRequest`, `Stop`, `SubagentStart` and `SubagentStop`.

- `PermissionRequest` fires when a command needs more than the sandbox allows, after `PreToolUse` and before the approval prompt. It carries `tool_name` and `tool_input.command`, with Codex's approval question in `tool_input.description`, and no `tool_use_id`, so it is joined to its `PreToolUse` by `turn_id` and command. It fired both for the command the developer approved and for the one refused.
- A network command first runs in the sandbox and fails: `PreToolUse`, then `PostToolUse` with an empty `tool_response`. Codex then retries it escalated: a second `PreToolUse`, `PermissionRequest`, and on approval `PostToolUse` with the output. So `PostToolUse` also follows a command the sandbox let run but cut off from the network; a command refused at the prompt has none, and the turn ends without `Stop`.
- `Stop` fires at the end of each turn with `stop_hook_active` and `last_assistant_message`.
- Subagent tools are `collaborationspawn_agent` (`tool_input`: `task_name`, `fork_turns`, and `message`, which Codex encrypts) and `collaborationwait_agent`, not `spawn_agent`. `SubagentStart` and `SubagentStop` carry `agent_id` and `agent_type`; `SubagentStop` adds `agent_transcript_path` and `last_assistant_message`. The subagent's own tool events carry `agent_id` and `agent_type` and the parent's `session_id` and `turn_id`.
- No `SessionEnd` was recorded when the session closed. 0.164.0 sent one under `codex exec`.

## Consequences for the design

1. **The adapter contracts use agent-specific response shapes.** Claude Code and Codex expect `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": ..., "permissionDecisionReason": ...}}`. Cursor expects `{"permission": ..., "user_message": ..., "agent_message": ...}`. `specs/adapter/v1` and its examples now enforce these shapes.
2. **The hook client always answers; its own crash is the only thing that fails closed.** We register with `onFailure: block` (Claude Code) and `failClosed: true` (Cursor). The hook client then applies the category fail mode itself when the daemon is unreachable: it returns `allow` for open categories and `deny` for closed ones. This keeps the ADR-0006 rule: the hook client uses a small built-in matcher, not Cedar.
3. **Codex is guarded in P1, but without `ask` and without fail-closed.** An `ask` verdict maps to `deny` with a message telling the developer how to allow it. Optionally a matching execpolicy `prompt` rule can be generated as a backstop. Its `doctor` and timeline must say plainly that Codex coverage is fail-open. User-tier hooks also need a one-time hash trust in Codex (`/hooks`), so `guard install` has to walk the developer through it.
4. **Cursor needs per-event registration.** Register `beforeShellExecution` and `beforeMCPExecution` (they honor `ask`), `beforeReadFile` (secrets), and `preToolUse` for writes and deletes.
5. **Cursor runs Claude Code hooks by default ("Third-Party Imports").** A Privometry hook installed for Claude Code also fires inside Cursor. The hook client must detect the caller from the payload (`cursor_version` or `conversation_id` present) and the daemon must dedupe on `tool_use_id`. Otherwise one action is evaluated and logged twice.
6. **The adapter definition needs more fields:** the macOS managed path for Claude Code, `managed-settings.d/` directories, MDM sources, Codex `requirements.toml` and `CODEX_HOME`, and per-event response formats.
7. **Only Claude Code has a config-change event**, so the daemon's file watcher (`internal/config`) stays the primary source of `config_change` events.

## Still open

- [ ] Record Cursor payloads: install the recorder in a test project's `.cursor/hooks.json` and run one agent session in the IDE.
- [x] Record Codex payloads (0.164.0), including the hook-trust flow.
- [x] Record a Codex `PermissionRequest` from an interactive session with on-request approvals, and `Stop` and subagent events (0.165.0).
- [ ] Decide what Privometry does at a Codex `PermissionRequest`: it is a second checkpoint for commands that leave the sandbox, which the daemon has no role handler for yet.
- [ ] Find out whether interactive Codex sends `SessionEnd`.
- [ ] Record a Claude Code MCP call (`mcp_server` field) and a `WebFetch`.
- [ ] Measure the hook round trip each agent adds, to set the latency budget against real overhead.

## Reproducing

```bash
make hook-recorder
# register bin/hook-recorder -agent <product> -event <Event> -out <dir> for each event in a scratch project,
# run the agent, then sanitize the recordings before copying them into test/fixtures/.
```
