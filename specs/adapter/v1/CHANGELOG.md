# adapter/v1

## 1.0.0-draft.8 (2026-10-29)

- `detect.session_paths`: files the agent writes once a session is in use (its transcripts). agy and Codex fire their session-start hook only at the first prompt, so an idle session makes no hook call; a running agent now counts as silent only once one of these files has changed since it started. The shipped definitions list Claude Code `~/.claude/projects/*/*.jsonl`, Codex `~/.codex/sessions/*/*/*/rollout-*.jsonl`, Gemini CLI `~/.gemini/tmp/*/chats/*.json`, Copilot CLI `~/.copilot/session-state/*/events.jsonl` and Antigravity `~/.gemini/antigravity-cli/conversations/*.db`.

## 1.0.0-draft.7 (2026-10-28)

- `hooks.disable_settings`: JSON pointers and values that turn all of an agent's hooks off, read in every JSON and TOML config tier that holds settings or hooks. The shipped definitions list Claude Code `/disableAllHooks: true` and Codex `/features/hooks: false` and `/features/codex_hooks: false`; Gemini CLI, Copilot CLI and Cursor stay empty until confirmed on real agents.
- `detect.process_patterns`: path fragments that identify an agent whatever its program is called (`@anthropic-ai/claude-code/`, `claude/versions/`, `@openai/codex/`, `@google/gemini-cli/`, `@github/copilot/`), matched against the program and a script runtime's script.
- `detect.no_session_args`: long-running commands that start no session (`claude mcp serve`, `codex mcp-server`), never reported as silent agents.

## 1.0.0-draft.6 (2026-10-28)

- `detect.bypass_flags`: flags that make the agent skip its permission prompts or its hooks (an entry may name a value, matched as the next argument or after `=`). The shipped definitions list Claude Code `--dangerously-skip-permissions` and `--permission-mode bypassPermissions`, Codex `--dangerously-bypass-approvals-and-sandbox`, Gemini CLI `--yolo`, `-y` and `--approval-mode yolo`, Copilot CLI `--allow-all-tools` and `--yolo`, and Antigravity `--dangerously-skip-permissions`.
- Antigravity's observe-only events reply `{}`, as its documentation shows; the generated Go type keeps an empty `stdout` object apart from `null`.

## 1.0.0-draft.5 (2026-10-28)

- `hooks.registration` gains `antigravity_hooks`: Antigravity's `hooks.json`, where each top-level key names a hook holding event keys (Privometry writes `privometry` and leaves other hooks alone); `PreToolUse` and `PostToolUse` take matcher groups, other events a list of handlers; timeouts in seconds. Pre-tool replies carry a top-level `decision` (`allow`, `auto_approve`, `deny`, `ask`, `force_ask`, `deny_unless_prior_grant`), which the schema enforces.
- New shipped definition `antigravity`, from documentation (`verified: []`): the agy CLI, desktop app and IDE (global `~/.gemini/config/hooks.json`, workspace `.agents/hooks.json` behind folder trust), MCP servers in `mcp_config.json` (`serverUrl` for remote servers), rules (`AGENTS.md`, `GEMINI.md`, `.agents/rules/*.md`, global rule folders), skills and permissions; `PreToolUse`, `PostToolUse` and `SessionStart`. Request pointers may index arrays (`/workspacePaths/0`). Policy asks reply `force_ask`, so an earlier "Always Allow" does not skip them.
- Examples: the Antigravity definition; the adapter-set example now holds six adapters.

## 1.0.0-draft.4 (2026-10-28)

- `hooks.registration` gains `gemini_settings` (Gemini CLI `settings.json`: grouped like Claude Code, timeouts in milliseconds, decisions in a top-level `decision` of `allow` or `deny`) and `copilot_hooks` (a Copilot CLI hooks file of its own: `version: 1`, camelCase events, the command in `bash` or `powershell`, decisions in a top-level `permissionDecision` of `allow`, `ask` or `deny`). The schema enforces each reply shape.
- New shipped definitions, from documentation (`verified: []`): Gemini CLI (`~/.gemini/settings.json` and the project and system tiers, `GEMINI.md`, skills, MCP servers; `BeforeTool`, `AfterTool`, `BeforeAgent`, `SessionStart`, `SessionEnd`) and Copilot CLI (`~/.copilot/hooks/privometry.json`, repo `.github/hooks/*.json`, policy files, `copilot-instructions.md`, `AGENTS.md`, `~/.copilot/mcp-config.json`; `preToolUse`, `postToolUse`, `userPromptSubmitted`, `sessionStart`, `sessionEnd`). Copilot's `toolArgs` arrives as a JSON-encoded string; consumers decode a string `tool_input` that holds a JSON object.
- Examples: both definitions; the adapter-set example now holds five adapters.

## 1.0.0-draft.3 (2026-10-24)

- Hook events may set `timeout_seconds`, overriding `hooks.timeout_seconds` for agents that cap some events. Codex limits `SessionEnd` hooks to 3 seconds and warns on every run when one is registered with more.
- The shipped Codex definition is verified against payloads recorded from Codex CLI 0.164.0 (`test/fixtures/codex_cli/0.164.0`): `UserPromptSubmit` carries `turn_id` (no `prompt_id`), and the definition now registers `PostToolUse` and `SessionEnd`.

## 1.0.0-draft.2 (2026-10-23)

- MCP source pointers may contain a whole-segment `*` wildcard. The Claude Code definition uses `/projects/*/mcpServers` to discover project-scoped servers in `~/.claude.json`.
- The Claude Code definition includes its installed-plugin registry at `~/.claude/plugins/installed_plugins.json`.
- `memory_files` (PRD SCAN-01): files an agent loads as standing instructions or memory, with `tier`, `kind` (`instructions`, `rules`, `memory`), `format`, `paths`, and `nested` (project tier only: the same path in any folder below the repo root), `imports` (the agent follows `@path` imports) and `written_by_agent` (automatic memory).
- The shipped definitions list Claude Code (`CLAUDE.md` at managed, user and project tiers, `CLAUDE.local.md`, `.claude/rules/`, automatic memory in `~/.claude/projects/*/memory/`), Codex CLI (`AGENTS.md`, `AGENTS.override.md`, experimental memories) and Cursor (`.cursor/rules/*.mdc`, moved here from `config_tiers`, plus `AGENTS.md` and `.cursorrules`).
- `tool_targets.*.content`: where a tool's written text lives (Claude Code `Write` `/content`, `Edit` `/new_string`, `NotebookEdit` `/new_source`), so the content scanner checks it before the write.
- `detect.app_binaries`: the agent's own binary inside a desktop app. Its presence means the app is installed, and it answers `version_cmd` when the binary on PATH is missing or broken. The Codex definition lists the engine inside the ChatGPT app (`/Applications/ChatGPT.app/Contents/Resources/codex`, run by the Codex desktop app as `codex app-server`, reading the same `~/.codex` config and hooks) and is now named "Codex".
- Examples: `memory_files` in the Claude Code example; 2 new invalid examples.

## 1.0.0-draft.1 (2026-10-23)

- Replies are defined per hook event, with the verdicts each event honors and a `fallback` for verdicts it cannot express. The schema requires a `fallback.ask` whenever an enforcing event cannot ask.
- Corrected reply shapes (Contracts v1 used a flat `permissionDecision`):
  - Claude Code and Codex: `{"hookSpecificOutput": {"hookEventName", "permissionDecision", "permissionDecisionReason"}}`.
  - Cursor: `{"permission", "user_message", "agent_message"}`.
  The schema enforces the right shape for each `hooks.registration` value.
- New sections: `verified` (fixture provenance), `hooks.registration`, `fail_closed_option`, `trust`, `imported_by`, `payload_markers`, `tool_targets`, `mcp_tools`.
- Examples: Claude Code (verified against 2.1.304 fixtures), Cursor and Codex (documentation only), and 10 invalid definitions.
- `adapter-set.schema.json`: the signed set of adapter definitions (`set_version`, `min_sensor_version`). Example generated from the three definitions by `scripts/gen-conformance`; 3 invalid examples.
