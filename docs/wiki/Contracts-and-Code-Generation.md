# Contracts and Code Generation

The `specs/` tree is the language-neutral compatibility boundary between the Go edge, Java platform, tooling, and external integrations.

## Contract families

| Contract | Purpose |
| --- | --- |
| `common/v1` | Shared IDs, timestamps, DSSE envelopes, and key sets |
| `event-schema/v1` | Edge audit and telemetry events |
| `policy/v1` | Policy documents, signed bundles, and Cedar entity model |
| `adapter/v1` | Agent adapter definitions and signed adapter sets |
| `rulepack/v1` | Rule-pack metadata, rules, and test cases |
| `detectorpack/v1` | Content detector packs and detector definitions |
| `riskfeed/v1` | MCP and skill reputation feed |
| `entitlements/v1` | Signed entitlements and offline license files |
| `release/v1` | Signed self-update manifests |
| `edge-api/v1` | OpenAPI and message schemas for edge/platform communication |
| `account-api/v1` | OpenAPI and message schemas for registration (a CLI sign-in key or a passkey, PIN on the device) and console sign-in |

## Source-of-truth rules

- JSON Schema 2020-12 defines data shape and structural constraints.
- OpenAPI defines HTTP operations and references message schemas.
- Cedar schema defines policy entities, actions, and context.
- Valid and invalid examples define conformance expectations.
- Semantic Go tests enforce rules that are awkward or impossible to express structurally.
- Changelogs describe contract evolution.

## IDs and media types

Schema IDs use `https://privometry.dev/specs/...`. Signed artifacts use media types under `application/vnd.privometry.*+json`. These values are part of signatures and compatibility checks; changing one requires a new contract version and regenerated/reissued signatures.

## Generated Go types

`scripts/gen-types` reads the schemas and writes `.gen.go` files under `internal/`. Generate them with:

```sh
make generate
```

Check reproducibility without modifying files:

```sh
make check-generated
```

Never hand-edit generated types. Add generator support when a new schema construct is required.

## The `pkg/edge` facade

Go doesn't let another module import `internal/` packages, so `pkg/edge` is the only public API for a connected build. Its subpackages, such as `pkg/edge/contract` and `pkg/edge/signing`, re-export the names the connector uses. `scripts/gen-facade` writes them from `pkg/edge/facade.txt`, one line per internal package:

```text
internal/signing signing Envelope Sign Verify
internal/ipc edgetest Request Version:IPCVersion
```

A `Name:Other` entry exports `Name` as `Other`. Add a name to the list and run `make generate`, rather than editing a `facade.gen.go` file. The generator fails when an exposed signature uses a type the facade doesn't export. Everything in `pkg/edge` is public API, so add only what the connector needs.

## Signed conformance vectors

`scripts/gen-conformance` deterministically creates DSSE envelopes and verification cases under `specs/conformance/signatures/`. Vectors cover valid signatures, wrong roles, unknown keys, expired/not-yet-valid keys, tampered payloads, payload-type confusion, rotations, and rollback attempts.

Both Go and Java verifiers must run the same vectors. A vector change should be reviewed as a security-sensitive compatibility change.

## Making a contract change

1. Decide whether the change is backward-compatible within the current version.
2. Update the schema and changelog.
3. Add valid and invalid examples.
4. Update OpenAPI or Cedar schema when affected.
5. Run `make generate`.
6. Run `make test` and `make check-generated`.
7. Regenerate Java types/stubs in `privometry-platform/contracts`.
8. Test old readers against new data and new readers against old data when compatibility is expected.

Create a new version directory for removals, semantic reinterpretation, stricter requirements that reject previously valid documents, or identifier/media-type changes.

## Validation behavior

The Go edge embeds `*.schema.json` files and compiles them without network access. Each schema `$id` must exactly match its repository path under the Privometry schema base. YAML inputs are converted into JSON-compatible values before schema validation and strict decoding rejects unknown generated fields.

## Cross-language integration

The Java platform should consume a versioned artifact produced from this repository rather than copying schemas manually. Generated Java packages should retain the contract version, and CI should validate the shared examples and signature vectors.
