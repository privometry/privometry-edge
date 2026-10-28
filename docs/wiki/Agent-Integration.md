# Agent Integration

Agent integrations are data-driven. An adapter definition describes discovery, configuration tiers, memory files, hook installation, native events, normalized tool kinds, argument pointers, response templates, trust requirements, and posture checks.

## Supported adapters

| Agent | Adapter ID | Version range | Registration | Important behavior |
| --- | --- | --- | --- | --- |
| Claude Code | `claude_code` | `>=2.1.295 <3.0.0` | `claude_settings` | Supports allow, ask, deny and fail-closed `onFailure` |
| Codex | `codex_cli` | `>=0.14.0 <1.0.0` | `codex_hooks` | Captures query metadata through `UserPromptSubmit`; requires hook trust; ask falls back to deny; crashes/timeouts fail open in the host |
| Cursor | `cursor` | `>=1.7.0 <3.0.0` | `cursor_hooks` | Dedicated shell/MCP events support ask; other pre-events may map ask to deny |
| Gemini CLI | `gemini_cli` | `>=0.26.0 <1.0.0` | `gemini_settings` | `BeforeTool` takes allow or deny (ask falls back to deny); hooks fail open on crash, timeout or bad output; timeouts are written in milliseconds. From documentation, not yet recorded |
| Antigravity | `antigravity` | `>=1.1.21 <2.0.0` | `antigravity_hooks` | One global hooks file serves the agy CLI, desktop app and IDE; Privometry adds a hook named `privometry`. `PreToolUse` takes allow, ask (sent as `force_ask`) or deny and reportedly fails closed; MCP tools carry no server name. From documentation, not yet recorded |
| Copilot CLI | `copilot_cli` | `>=1.0.0 <2.0.0` | `copilot_hooks` | Privometry writes its own `~/.copilot/hooks/privometry.json`; `preToolUse` takes allow, ask or deny and fails closed on crash (open on timeout); `toolArgs` arrives as a JSON string. From documentation, not yet recorded |

Adapter source files are under `adapter-defs/`. Generated Go types are under `internal/adapters/registry/`.

## Integration lifecycle

1. The scanner detects an agent by binaries, processes, app binaries, and configuration paths.
2. `privometry guard install` selects the adapter's free/user hook location unless enterprise deployment manages the configuration.
3. The agent invokes `privometry-hook <agent> <event>` with its native JSON payload on standard input.
4. The daemon validates the adapter and event, reads values through JSON pointers, maps the native tool to a normalized action, and evaluates policy.
5. The adapter renders allow, ask, deny, or observation output in the host's required shape.
6. Post-tool and lifecycle events update session state, content findings, and the timeline.

Gemini CLI was retired for consumer tiers on 2026-06-18 in favor of Antigravity CLI (`agy`), whose hooks live in `.agents/hooks.json` with a different payload; Gemini CLI remains available with Gemini Code Assist Standard and Enterprise licenses and paid API keys. Both adapters ship; they share `~/.gemini/GEMINI.md`.

Codex query capture uses the observe-only `UserPromptSubmit` event. The daemon records the prompt ID, Unicode character count, and a device-keyed HMAC fingerprint so identical queries can be correlated without persisting query text. Existing installations must rerun `privometry guard install --agent codex_cli` and trust the updated hook set with Codex `/hooks`.

## Adapter definition sections

- `detect`: binaries, processes, app paths, version command, and version parsing inputs.
- `env_overrides`: agent-specific configuration-root environment variables.
- `config_tiers`: user, project, local, and managed settings with formats and capabilities.
- `mcp_sources`: locations and document pointers containing MCP server configuration; a whole-segment `*` visits dynamic scopes such as Claude Code's per-project server maps.
- `memory_files`: instruction, memory, and skill paths, including nested project behavior.
- `hooks`: registration strategy, install paths, timeout, trust, fail-closed setting, events, request pointers, and response templates.
- `tool_kinds`: native tool name to normalized action mapping.
- `tool_targets`: JSON pointers for command, path, URL, content, or patch arguments.
- `mcp_tools`: native naming template and optional server pointer.
- `posture_checks`: scanner checks meaningful for this agent.

## Adding an adapter

1. Copy the closest definition in `adapter-defs/`.
2. Choose a stable snake-case `agent` identifier and human-readable name.
3. Record an explicit supported version range; do not claim versions that were not tested.
4. Add every configuration tier and distinguish user-managed from centrally managed paths.
5. Define hook events from the vendor's current protocol. Use JSON Pointer syntax beginning with `/`.
6. Define native response bodies for each supported verdict. If the host cannot represent `ask`, declare a conservative fallback.
7. Mark trust steps and fail-closed controls accurately.
8. Add sanitized real payload fixtures under `test/fixtures/<agent>/<version>/`.
9. Extend generated enums in the schema when introducing a new agent identity, then run `make generate`.
10. Add registry, scanner, guard, hook, and round-trip tests.

## Security requirements

- Never log the raw hook payload. Payloads may contain commands, file contents, source code, URLs, credentials, and private paths.
- Do not forward fields that are not needed for policy evaluation.
- Response templates must not echo raw secret-bearing arguments.
- Installation must preserve unrelated hooks and settings and must be reversible.
- Project configuration is untrusted input; managed configuration must pass ownership and permission checks.
- An unknown event or malformed payload must produce an explicit safe result, not silently bypass policy.
- Deduplicate overlapping hook systems, such as Cursor importing Claude Code hooks.

## Validation checklist

```sh
go test ./internal/adapters/registry ./internal/scanner ./internal/guard ./internal/daemon
privometry scan --format json
privometry guard install --agent <agent> --dry-run
privometry guard status --agent <agent>
privometry doctor
```

Test normal actions, destructive commands, secret reads, uploads, MCP calls, unavailable daemon behavior, hook timeout, configuration mutation, and the host's trust workflow.

## Updating an existing adapter

Prefer data-only updates when the host protocol remains representable by the adapter schema. Change the schema only when the protocol introduces a concept that cannot be expressed safely. Bump `SetVersion` in `adapter-defs/embed.go` with every change (a test pins each version's content), and set the minimum compatible sensor version when signing. Sensors already in the field get data-only updates through a signed adapter set (`privometry definitions update`); see `docs/definitions.md`.
