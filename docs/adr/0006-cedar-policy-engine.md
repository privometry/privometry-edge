# ADR-0006: Use Cedar as the policy engine

- Status: Accepted
- Date: 2026-10-23

## Context

The same policy must produce identical verdicts on the Go edge and in the Java control plane and MCP gateway, with bounded latency on the hook path. The candidates were Cedar and OPA (Rego). OPA has no native Java evaluator and its cost depends on how each policy is written. Cedar has official Go (`cedar-go`) and Java bindings, bounded evaluation, and no network or open-ended computation. Cedar has no regex, and `cedar-go` lacks a stable schema validator, formatter, partial evaluation and templates.

## Decision

Use Cedar internally. Developers keep writing Privometry's YAML policy language (`privometry.policy/v1`), which the edge and the policy service compile to Cedar.

- Shell intent parsing, path classification, glob and regex matching stay in Go extractors. They turn each action into facts (`intent`, `path_class`, `program`, `untrusted_input_seen`, ...) and Cedar decides only on those facts.
- `deny` rules compile to `forbid`; `ask` and `allow` compile to `permit`, annotated with `@verdict`. Monitor rules form a second policy set whose result is recorded as `would_verdict`.
- The control plane validates every compiled policy against `privometry.cedarschema` with the Java bindings before signing a bundle, so the edge never needs the Go validator.

## Consequences

- Shared vectors in `specs/conformance/policy-verdicts/` run in CI against `cedar-go` and the Java bindings; any disagreement fails both builds.
- The hook client does not embed Cedar. For closed fail-mode categories it carries a small hard-coded matcher and asks the daemon for everything else.
- Policy authors cannot use regex; new matching needs become new extractor facts.
