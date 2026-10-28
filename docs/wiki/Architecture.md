# Architecture

Privometry places a local policy boundary between AI coding agents and the tools they invoke. The edge remains useful offline and is designed so a platform or licensing failure cannot turn off local enforcement.

## Runtime flow

```text
AI coding agent
      │ native hook event
      ▼
privometry-hook ── timeout/unavailable ──► built-in fail mode + local spool
      │ user-only IPC
      ▼
privometryd
  ├─ adapter normalization
  ├─ intent and target extraction
  ├─ content detectors and redaction
  ├─ merged policy evaluation
  ├─ agent-native response rendering
  └─ redacted SQLite timeline
      │ planned optional signed sync/upload
      ▼
Privometry Java platform
```

## Components

### CLI

`cmd/privometry` is the operator interface. It performs read-only scans, manages daemon and hook installation, tests policy, queries the timeline, creates diagnostic bundles, and performs signed self-updates.

### Hook client

`privometry-hook` is deliberately small and fast. It accepts an agent name and event name, reads the native payload from standard input, and calls the daemon over a Unix socket or named-pipe abstraction. If the daemon does not answer within the configured budget, the hook applies locally cached fail modes and spools the resulting event.

### Daemon

`privometryd` is a per-user process. It owns session state, policy caches, content scanning, timeline persistence, integrity checks, and future cloud synchronization. It never runs as root.

### Policy engine

The engine extracts normalized facts from shell commands, file targets, URLs, MCP calls, and session state. YAML policy is compiled to Cedar. The final verdict is the strongest applicable result across built-in, organization, repository, and user sources.

### Scanner

The scanner discovers installed agents, versions, configuration tiers, MCP servers, hooks, skills, plugins, memory files, and risky settings. It produces table, JSON, or SARIF output without returning secret values.

### Content engine

Detector packs inspect commands, URLs, MCP arguments, written content, tool output, and instruction files. Findings contain classifications, masked excerpts, and fingerprints rather than raw secrets.

### Timeline

The SQLite store provides monotonically sequenced local events. The CLI and embedded web UI query the same store. When the daemon is unavailable, the CLI opens it read-only.

### MCP shim

`privometry-mcp-shim` is reserved for enforcing policy around local stdio MCP servers. Hosted and in-process tools still depend on the host agent's hook coverage.

## Trust boundaries

| Boundary | Required controls |
| --- | --- |
| Agent payload → hook | Size bounds, native event mapping, untrusted-input handling |
| Hook → daemon | Per-user IPC path, restrictive permissions, protocol versioning, timeout |
| Policy/artifact → edge | JSON Schema validation, DSSE verification, role-scoped Ed25519 keys, expiry and rollback checks |
| Event → disk/cloud | Secret and PII redaction before persistence or upload |
| Release → installation | Signed manifest, platform match, digest and size validation, no downgrade |
| License → enforcement | Entitlements may limit paid features; local protection remains active |

## Policy layers

From most centrally governed to most local:

1. Built-in rule packs shipped in the binary.
2. Signed organization policy bundle.
3. Repository policy at `.privometry/policy.yaml`.
4. User policy at `~/.privometry/policy.yaml`.

Lower layers cannot weaken a locked rule. Deny takes precedence over ask, and ask takes precedence over allow when multiple rules apply.

## Versioned contracts

Contracts under `specs/` are language-neutral. The Go edge embeds them and generates types from them; the Java platform generates matching Java types and server stubs. Signed conformance vectors ensure both implementations agree on artifact verification and policy semantics.

## Architectural decisions

The durable decisions are recorded in `docs/adr/`, including the Go edge, the rule that licensing never disables protection, and Cedar as the embedded policy engine.
