# Contributing to privometry-edge

Privometry sits on a security boundary. Changes must preserve protection when the daemon, network, cloud service, or license service is unavailable.

## Before you start

1. Read the [developer setup](docs/wiki/Developer-Setup.md) and [architecture](docs/wiki/Architecture.md).
2. Open an issue before making a public-contract, policy-semantics, storage, or trust-root change.
3. Keep licensing separate from billing and never make local protection conditional on licensing.

## Local checks

```sh
make fmt
make lint
make test
make check-generated
make build
```

Run `make race` for changes to the daemon, IPC, timeline, session state, config watching, or concurrent scanners.

## Generated files

Schemas under `specs/` are authoritative. When a contract changes, run:

```sh
make generate
make check-generated
```

Commit the schema, examples, generated Go types, and regenerated conformance vectors together. Do not hand-edit files ending in `.gen.go`.

## Pull requests

- Keep changes focused and explain their security effect and failure mode.
- Add tests for success, denial, malformed input, timeout, and unavailable dependency paths where relevant.
- Update the wiki and command examples when behavior or flags change.
- Add an ADR under `docs/adr/` for an architectural decision that is difficult to reverse.
- Never include real credentials, customer data, raw hook recordings, or unredacted diagnostic bundles.

## Commit style

Use an imperative subject that describes the outcome, for example `Add Gemini adapter validation`. Separate generated output from unrelated refactoring when practical.

## Review expectations

Reviewers should verify least privilege, fail-mode behavior, redaction before persistence or upload, deterministic contract generation, backward compatibility, and the effect on all supported operating systems and agents.
