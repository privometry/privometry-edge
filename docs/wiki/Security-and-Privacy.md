# Security and Privacy

Privometry observes security-sensitive agent activity. Its design minimizes collection, keeps enforcement local, and treats every external input as untrusted.

## Core guarantees

- Local scanning and protection continue offline.
- License failures do not disable local protection.
- The daemon runs as the current user, not root.
- Runtime state and IPC are user-only.
- Raw secrets and full sensitive inputs are not stored or uploaded.
- Signed artifacts are verified before use.
- A failed update leaves the installed version intact.
- Hook removal and configuration drift produce integrity signals.

## Data handling

Potentially sensitive inputs include commands, arguments, paths, repository identities, MCP arguments and results, file content, prompts, agent responses, configuration, and environment metadata.

Before persistence or upload, the edge applies redaction and normalization. Local timeline targets are redacted at the database boundary by default, including fallback-spool imports. Events use privacy levels and carry masked excerpts, classifications, or keyed fingerprints where correlation is needed. Integrations must not add debug logging that bypasses the redaction boundary.

## Local storage

The default data directory is `~/.privometry` on macOS/Linux and `%LOCALAPPDATA%\Privometry` on Windows. Directories must be owned by the current user with no group/other permissions (on Windows, an access list granting only the user, SYSTEM and Administrators); files are private. Symlinks and foreign-owned locations are rejected.

SQLite contains the redacted timeline. Fail-mode and spool files may still reveal that an operation occurred and must be treated as sensitive operational data.

## IPC

The daemon uses a per-user Unix socket on macOS/Linux and a per-user named pipe on Windows. Requests are versioned and size-bounded. The socket directory and socket permissions are verified; the pipe admits only the user, refuses remote clients, and clients refuse a pipe another account owns. IPC is local transport, not an authorization substitute; callers and payloads remain untrusted.

## Community packs

Rule and detector packs from other publishers are trusted per publisher key, by the person, with `privometry trust add` (which shows the key's fingerprint). A key signs packs only under its own publisher name, the `privometry` publisher is reserved for the release key, and every pack is verified again whenever it loads, so removing a key stops its packs at the next load. Rule packs only apply where a policy extends them. See `docs/community-packs.md`.

## Artifact trust

Policy bundles, entitlements, licenses, risk feeds, adapter sets, key-set rotations, and release manifests use DSSE envelopes with Ed25519 signatures. Verification binds the payload type, payload bytes, key ID, key role, and key validity period. Key-set updates enforce ordered trust and prevent rollback.

## Hook failure behavior

The hook client has built-in fail modes for daemon outage or timeout. Host-agent limitations are documented in adapter definitions. A platform or cloud outage is never used as an allow signal. Where an agent cannot represent `ask`, the adapter uses a declared conservative fallback.

## Content scanning

Detector packs find credential patterns, injected instructions, safety weakening, hidden Unicode/content, and encoded instructions. Detectors use keyword prefilters, bounded input, masked evidence, allowlists, entropy/pattern/structure signals, and salted fingerprints. Findings must not preserve the full detected credential.

## Threats to consider during review

- Hook bypass, removal, replacement, or trust revocation
- Malicious project configuration or instructions
- Symlink and path traversal attacks
- Cross-user file or socket access
- Policy downgrade, shadowing, or exception abuse
- Payload-type confusion and key-role confusion
- Replay, rollback, duplicate event, and sequence-gap behavior
- Secret leakage through logs, errors, reports, or UI
- Resource exhaustion from oversized payloads or pathological patterns
- Update replacement or partial installation

## Reporting

Follow `SECURITY.md`. Never put vulnerability details or real secrets in a public issue.
