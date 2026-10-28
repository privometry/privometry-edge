# Policy Integration

Privometry policy is authored in YAML, validated against `privometry.policy/v1`, converted to normalized facts, compiled to Cedar, and evaluated locally.

## Policy locations

| Layer | Location | Purpose |
| --- | --- | --- |
| Built-in | Embedded `rulepacks/` | Default catastrophic, secret, exfiltration, MCP, and instruction protection |
| Organization | Signed policy bundle | Centrally governed and optionally locked rules |
| Repository | `.privometry/policy.yaml` | Rules committed with a codebase |
| User | `~/.privometry/policy.yaml` | Developer-specific additions and permitted overrides |

The strongest matching verdict wins. A lower layer cannot loosen a locked higher-layer rule.

## Minimal repository policy

```yaml
schema: privometry.policy/v1
name: repository-defaults
description: Additional controls for this repository
extends:
  - privometry/core-catastrophic@^1
  - privometry/secrets@^1
defaults:
  unmatched: auto
rules:
  - id: ask-before-production-deploy
    effect: ask
    message: Confirm deployment to production.
    when:
      action: shell_exec
      program: deploy
      args_contain: production
```

Use examples under `specs/policy/v1/examples/valid/` and `policies/examples/` as the canonical syntax reference.

## Normalized actions and facts

The engine recognizes actions including:

- `shell_exec`
- `file_read`, `file_write`, `file_delete`
- `network_fetch`, `web_search`
- `mcp_call`
- `subagent_spawn`

Intent extraction adds facts such as program, subcommand, path class, target class, repository, remote host, secret detection, injection detection, untrusted-input state, risk, and MCP catalog status. Unknown or ambiguous input remains explicit; policy must not assume successful parsing.

## Rule packs

A rule pack contains:

```text
pack.yaml          metadata, compatibility, categories, fail modes
rules/*.yaml       policy rules
tests/*.test.yaml  required behavior examples
```

Shipped packs include:

- `privometry/core-catastrophic`
- `privometry/secrets`
- `privometry/exfiltration`
- `privometry/mcp-allowlist`
- `privometry/agent-instructions`

Pack IDs and rule IDs are public compatibility identifiers. Avoid renaming them after release.

## Content allowlists

Policy files can list `allowlist` entries for content findings people have checked, such as fake keys in test fixtures. Each entry names detectors (`privometry/credentials:aws-access-key`, or `privometry/credentials:*`) and narrows them by repo-relative path globs, exact values, or both, with a reason and an optional `expires_at`. Allowlisted findings are dropped before they become policy facts, in the daemon and in `privometry scan`. See `docs/content-scanning.md`.

## Testing

Test the current local policy:

```sh
privometry policy test
```

Test one file or pack:

```sh
privometry policy test .privometry/policy.yaml
privometry policy test rulepacks/secrets
```

Explain synthetic actions:

```sh
privometry policy test --command "git push --force origin main"
privometry policy test --read ~/.ssh/id_ed25519
privometry policy test --fetch https://example.invalid/upload --untrusted
```

Policy tests belong in a sibling `tests/` folder unless `--tests` selects another location.

## Session-aware policy

The daemon tracks whether a session consumed untrusted content or detected injected instructions. Later actions can become more restrictive—for example, an upload after untrusted input or an edit to agent memory after injection. Session IDs come from the host adapter and must be treated as untrusted identifiers.

## Fail modes

When the daemon cannot decide in time, the hook client applies shipped fail modes. Catastrophic actions remain blocked; secret and exfiltration behavior remains conservative. Policy authors must not use daemon availability as a way to weaken protection.

## Organization bundles

The platform distributes policy as a DSSE envelope with media type `application/vnd.privometry.bundle+json`. The edge verifies the signature role, key validity window, payload type, schema, sequence/version rules, and embedded entitlements before activation. The last verified bundle remains usable offline.

## Review checklist

- Every deny and ask message is safe to show and contains no raw secret.
- Rules cover malformed, unknown, and indirect forms of the action.
- Exceptions are narrow, expire, and match validated facts.
- Overrides refer to qualified rule IDs.
- Locked rules cannot be weakened by repository or user policy.
- Tests cover allow, ask, deny, untrusted-session, and fail-mode behavior.
