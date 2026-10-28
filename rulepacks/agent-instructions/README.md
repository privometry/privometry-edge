# privometry/agent-instructions

Protects the files agents load as standing instructions and memory (`target_class: memory_file`): `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.claude/rules/`, `.cursor/rules/`, Copilot instructions and agents' automatic memory. Ships inside the Privometry sensor and is on by default.

| Rule | Verdict | Catches |
|---|---|---|
| `ask-instruction-edit` | ask | An agent editing its own instruction files, by tool or shell redirect. Automatic memory folders (`~/.claude/projects/*/memory/`, `~/.codex/memories/`) are left to the agent |
| `block-memory-edit-after-injection` | deny | Any memory or instruction edit after the session read content flagged as injected instructions (`injection_seen`) |
| `ask-safety-weakening-write` | ask | Writing text that tells agents to skip approvals or ignore instructions (`injection_detected` medium or high) |
| `ask-hidden-content-write` | ask | Writing invisible characters, hidden HTML-comment instructions or encoded instructions (`hidden_content`) |

The content facts come from the detector packs in `detectorpacks/`.
