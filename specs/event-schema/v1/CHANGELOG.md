# event-schema/v1

## 1.0.0-draft.6 (2026-10-28)

- `integrity.check` gains `hooks_disabled` (a setting turns the agent's hooks off, or Privometry's own entry is off), `hooks_silent` (an agent has run for minutes and its hooks never called Privometry), `sensor_stopped` (privometryd was down for more than five minutes outside a shutdown or reboot) and `sensor_uninstalled` (`privometry daemon uninstall`); privometry-oss `docs/spikes/bypass-detection.md`.
- `integrity.reason`: `setting`, `config_dir_override`, `untrusted_hook` or `unknown` for `hooks_silent`, and `killed` or `stopped` for `sensor_stopped`.
- `integrity.down_seconds` and `integrity.actions_while_down` for `sensor_stopped`.

## 1.0.0-draft.5 (2026-10-28)

- `integrity.check` gains `hooks_bypassed`: a running agent was started with a flag that skips its permission prompts or its hooks (adapter `detect.bypass_flags`), such as Antigravity's `--dangerously-skip-permissions`, which turns its hooks off. `detail` names the flag; the command line is never read into the event.

## 1.0.0-draft.4 (2026-10-28)

- `content_finding.fingerprint` says which key makes it: the organization's hash key on an enrolled device, so the same secret matches across devices (PRD SCAN-15); a device-local key otherwise, and those fingerprints are not uploaded. No shape change.
- A `config_change` for a memory file a person restored from a kept version (PRD SCAN-14, `privometry memory restore`) has `changed_by: person`; the version stays local, in `ext.x_privometry_restored_from_version`.

## 1.0.0-draft.3 (2026-10-28)

- Inventory items gain optional `package` (the package an MCP server runs, without its version) and `host` (an HTTP MCP server's host), so organization catalogs can recognize servers by package or host as well as by name (PRD CP-09). Never a command line or a full URL.
## 1.0.0-draft.2 (2026-10-23)

- Content scanning (PRD SCAN-01 to SCAN-11, Contracts v1 `content_finding`):
  - new event type `content_finding` with its section: `detector_id` (`<pack>:<name>`), `pack_version`, `category` (six), `severity`, `confidence`, `source` (eight), `secret_type`, `location` (`path_class`, salted `path_hash`, `line`, `tier`, `agent_product`; never a raw path), `fingerprint`, `action_taken`;
  - `secret_type` is required for credentials, and `secret_type` and `fingerprint` are only allowed on credentials;
  - findings from `action_argument`, `file_write` or `tool_output` must carry `agent` and `action`;
  - `action.secret_types`: credential kinds found in an action, never values;
  - `context.injection_seen`: stays true for the rest of a session once injected content was read.
- `secret_type` is a snake_case name rather than an enum, so detector packs can add kinds.
- `config.holds` gains `instructions`, `rules` and `memory` for agents' memory and instruction files, and `config.changed_by` (`person`, `agent`, `unknown`) records who changed one (PRD SCAN-02).
- Examples: 14 valid, 27 invalid.

## 1.0.0-draft.1 (2026-10-23)

- Envelope and the five event types from Contracts v1 (`action`, `config_change`, `integrity`, `fail_mode`, `inventory`), with required sections per type and `mcp` required for `mcp_call` actions.
- Defined the type-specific sections the contract left open: `config`, `integrity`, `fail_mode`, `inventory`.
- Additions beyond Contracts v1, from the hook spike:
  - `agent.native_session_id`: the agent's own session ID; `session_id` stays a Privometry `ses_` ID.
  - `action.tool_use_id`: lets the daemon dedupe when Cursor also runs Claude Code hooks.
  - `decision.native_verdict`: what the agent actually received when it cannot express the verdict (Codex has no ask).
  - `decision.would_verdict` required in monitor mode, where `verdict` must be `allow`.
- Examples: 10 valid, 19 invalid.
