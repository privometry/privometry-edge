# Fixtures

Real agent config files and hook payloads, organized as `<agent>/<version>/<kind>/`. A `documented/` folder instead of a version holds payloads built from vendor documentation, used until real ones are recorded; an adapter whose only fixtures are documented has `verified: []`. Adapter tests parse every file here, so a vendor change that breaks parsing fails CI (see Contracts v1, "Adapter fixtures").

| Path | Source | Recorded |
|---|---|---|
| `claude_code/2.1.304/hooks/` | Headless session with `scripts/hook-recorder` on every event | 2026-10-23 |
| `codex_cli/0.164.0/hooks/` | Three `codex exec` sessions with `scripts/hook-recorder` on every event: shell commands, `apply_patch` (update and add), a local stdio MCP tool, and `rm -rf build .` stopped by the read-only sandbox | 2026-10-24 |
| `codex_cli/0.165.0/hooks/` | Interactive `codex --sandbox workspace-write --ask-for-approval on-request` session with `scripts/hook-recorder` on nine events: listing, an `apply_patch` update, `curl` blocked by the sandbox then approved through `PermissionRequest`, a write outside the project refused at `PermissionRequest`, and a subagent (`collaborationspawn_agent`, `SubagentStart`, `SubagentStop`). No `SessionEnd` fired | 2026-10-29 |
| `gemini_cli/documented/hooks/` | Constructed from the Gemini CLI hooks and tools references (field names, `tool_input` keys, `mcp_context`); not recorded. Replace with a recorded `gemini_cli/<version>/` once a signed-in session is available | — |
| `copilot_cli/1.0.105/hooks/` | Interactive session with `scripts/hook-recorder` on every event: `bash`, `view`, `apply_patch` (update and add), `web_fetch`, a local stdio MCP tool, and `rm -rf build` refused at Copilot's prompt | 2026-10-29 |
| `copilot_cli/documented/hooks/` | Constructed from the GitHub Copilot CLI hooks reference (camelCase events, `toolArgs` as a JSON string). Kept beside the recording: it covers the JSON-string form of `toolArgs` and policy cases the session did not hit | — |
| `cursor/3.27.22/hooks/` | IDE agent session with `scripts/hook-recorder` on 13 events: listing, reading and editing `notes.md`, creating `todo.md`, `curl`, a local stdio MCP tool, and `rm -rf build`. `claude-*.json` are the same session's calls to the project's Claude Code hooks, which Cursor runs with its own payload | 2026-10-29 |
| `antigravity/1.4.10/hooks/` | Interactive `agy` session with `scripts/hook-recorder` on six events (the definition's three plus `PreInvocation`, `PostInvocation` and `Stop`): `ls`, `read_file`, `edit_file`, `write_file`, `curl`, a local stdio MCP tool through `call_mcp_tool` (after agy read the tool's schema from its own folder), and `rm -rf build` refused at agy's prompt | 2026-10-29 |
| `antigravity/documented/hooks/` | Constructed from the Antigravity hooks reference (named hooks, camelCase payloads, `toolCall.name` and `toolCall.args`, `workspacePaths`); not recorded. Kept beside the recording: its tool names (`view_file`, `write_to_file`, `replace_file_content`, `read_url_content`) were not seen in 1.4.10, and it covers policy cases the session did not hit | — |

Recording a new version, without touching the agent's user-level config:

```bash
go run ./scripts/hook-recorder setup -agent gemini_cli -project ~/scratch/rec-gemini
```

`setup` copies the recorder to a temporary folder and registers it for every hook event in the definition, in the agent's project-level hooks file inside the throwaway project (it refuses the home folder and a project that already has one). Start the agent there, trust the folder if it asks, and do what `setup` lists. Then:

```bash
go run ./scripts/hook-recorder sanitize -agent gemini_cli -version 0.12.0 -in <recordings folder> -project ~/scratch/rec-gemini
```

`sanitize` writes `<agent>/<version>/hooks/<event>-<tool>.json`, replacing the project, home folder, user name and host name with the placeholders below, and flags payloads that look like they hold a secret. Read every file before adding it.

Rules:

- Sanitize before committing: home directory becomes `/home/dev`, project paths `/home/dev/acme-api`, and nothing machine- or person-specific remains.
- Never commit secrets, real prompts with private content, or real MCP server URLs.
- Keep payloads byte-for-byte otherwise, including undocumented fields.
