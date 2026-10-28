# Testing and Release

## Test layers

| Layer | Coverage |
| --- | --- |
| Unit | Parsers, intent extraction, policy merge/compiler/engine, redaction, permissions |
| Contract | Every valid example passes and every invalid example fails |
| Conformance | Policy verdicts, redaction vectors, and DSSE signature behavior |
| Component | Scanner, daemon, hook client, IPC, timeline, updater, web UI |
| Adapter | Discovery, paths, hook mapping, install/uninstall, native replies |
| Race | Concurrent daemon, scanner, and storage paths |
| Release dry run | Cross-platform GoReleaser build and archive layout |

## Local release gate

```sh
make fmt
make lint
make test
make race
make check-generated
make build
```

Verify deterministic conformance output:

```sh
go run ./scripts/gen-conformance
git diff --exit-code -- specs
```

Tests that bind local sockets require an execution environment that permits Unix/TCP loopback listeners.

## Continuous integration

GitHub Actions is the only CI. On pull requests and `main`:

- `ci.yml` runs on Linux, macOS and Windows: gofmt (Linux), vet, race-enabled tests (Windows runs without the race detector, and runs the named-pipe, access-list, DPAPI and lock tests), the build, and checks that generated types and conformance vectors are up to date. It also runs golangci-lint and a GoReleaser snapshot.
- `security-scan.yml` is the repository's own gate, run with its own action (`./action`): it validates `.privometry/policy.yaml`, flags changed agent files and the repo policy, scans every changed file with the content detectors, uploads SARIF to code scanning and fails on a high or critical finding. This repo's detector packs, specs, tests and docs quote credentials and attack text on purpose; `.privometry/policy.yaml` allowlists them by path, so only new occurrences elsewhere fail the gate. Changing that file is itself flagged for review.
- `dependency-license-scan.yml` builds the deterministic CycloneDX 1.5 SBOM and the dependency-license policy report from the modules linked into the four release commands; a missing or unrecognized license fails it. CodeQL, spec validation and the wiki publish run in their own workflows.

`release.yml` runs on `v*` tags in three jobs: `build` (GoReleaser, no secrets), `sign` (the only job that can read the release key: the `PRIVOMETRY_RELEASE_KEY` secret of the protected `release` environment; it writes `release.json` with `scripts/release-manifest` and the signed `adapters.json` and `detectorpacks.json` with `scripts/sign-definitions`, and cannot write to the repo), and `publish` (creates the GitHub release with the archives, checksums and signed files). A manual run with a tag re-signs that release's `release.json` with a fresh expiry, since devices refuse an expired manifest. Make release keys with `scripts/release-keygen`; see `internal/trust/keys/README.md`.

Contract validation in Go is stronger than syntax-only validation: it compiles schemas and checks all positive and negative fixtures.

## Versioning

- Git tags use `vMAJOR.MINOR.PATCH`.
- Binaries report the semantic version without the `v` prefix when injected by GoReleaser.
- Public contract versions are independent directories such as `policy/v1`.
- Rule packs and detector packs have their own semantic versions and minimum sensor versions.
- Adapter sets, risk feeds, key sets, and bundles carry monotonic versions or sequences where their schemas require them.

## Build artifacts

GoReleaser builds static binaries for macOS and Linux on `amd64` and `arm64`:

- `privometry`
- `privometryd`
- `privometry-hook`
- `privometry-mcp-shim`

Archives include `LICENSE`, `NOTICE`, `README.md`, `privometry.cdx.json`, and `dependency-licenses.json`, plus a checksum manifest. Generate and inspect the compliance files locally with `make release-metadata`. Windows archives are zip files; `privometryd.exe` is built for the GUI subsystem so its logon task opens no console window. A Scoop manifest is generated into `dist/` (`skip_upload` until the bucket and release signing exist).

## Signed definitions

Adapter definitions and detector packs also ship as sets signed with the release key, so sensors in the field get data-only updates (`privometry definitions update`). Bump `SetVersion` in `adapter-defs/embed.go` or `detectorpacks/embed.go` with every change to those folders (`TestBuiltInSetVersionsArePinned` enforces it), then run `go run ./scripts/sign-definitions` and attach `adapters.json` and `detectorpacks.json` to the release. See `docs/definitions.md`.

## Signing requirements

The runtime understands signed releases, but repository release automation must not be considered production-ready until the release trust root, key custody, artifact signing, and rotation process are configured and audited.

A production release requires:

1. an offline or hardware-protected root key process;
2. role-specific release keys with validity windows;
3. a DSSE-signed `privometry.release/v1` manifest;
4. SHA-256 and size metadata for every platform archive;
5. published checksums and SBOM;
6. a tested rotation and revocation procedure;
7. a rollback-safe stable manifest endpoint.

Never commit private signing keys. The edge intentionally refuses self-update when it has no trusted release keys.

## Release procedure

1. Ensure `main` is green and generated output is clean.
2. Review contract, rule-pack, detector-pack, adapter, and migration changelogs.
3. Build and smoke-test each target architecture.
4. Create and sign the release manifest through the approved signing system.
5. Tag the exact commit.
6. Let the release workflow build immutable artifacts.
7. Verify downloaded artifacts independently before publishing the stable manifest.
8. Exercise `privometry update --check` and a full update from the previous supported version.
9. Verify daemon restart, hooks, policy, timeline, and offline behavior.

## Rollback

The self-updater refuses downgrades. An operational rollback is therefore a package-manager or explicit reinstall procedure, not an unsigned manifest change. Never weaken version or signature checks to recover a release.
