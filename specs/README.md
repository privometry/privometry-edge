# Privometry specs

Language-neutral contracts shared by the Go edge (this repo) and the Java platform. Each contract lives in `<name>/v1/` with its JSON Schema (2020-12), `examples/valid/`, `examples/invalid/` and a `CHANGELOG.md`.

| Folder | Identifier | Status |
|---|---|---|
| `common/v1` | shared `$defs`, DSSE envelope, key set | Draft |
| `event-schema/v1` | `privometry.event/v1` | Draft |
| `adapter/v1` | `privometry.adapter/v1`, `privometry.adapter_set/v1` | Draft |
| `policy/v1` | `privometry.policy/v1`, `privometry.bundle/v1`, `privometry.cedarschema` | Draft |
| `rulepack/v1` | `privometry.rulepack/v1`, `privometry.rules/v1`, `privometry.ruletest/v1` | Draft |
| `riskfeed/v1` | `privometry.riskfeed/v1` | Draft |
| `release/v1` | `privometry.release/v1` (signed self-update manifest) | Draft |
| `detectorpack/v1` | `privometry.detectorpack/v1`, `privometry.detectors/v1` (content detectors), `privometry.detectorpack_set/v1` (signed set) | Draft |
| `communitypack/v1` | `privometry.communitypack/v1` (a rule or detector pack signed by its publisher) | Draft |
| `conformance/` | policy verdicts, signatures, redaction | Draft |

The control-plane contracts (`edge-api/v1`, `account-api/v1`, `org-api/v1` and `entitlements/v1`) are private and live in privometry-connect, which builds the connected sensor. Their schemas `$ref` the ones here; `specs.NewSet` compiles both together. A bundle carries the organization's entitlements as an opaque DSSE envelope signed by the license key, so the edge needs only `common/v1` to check its shape.

Go code imports this folder as `github.com/privometry/privometry-edge/specs`: the schemas and `privometry.cedarschema` are embedded, and `specs.Validate` checks a JSON or YAML file against one.

## Generated Go types

`go run ./scripts/gen-types` (or `make generate`) writes Go types for every machine-written contract. CI runs it with `-check` and fails if any generated file is stale.

| Schemas | Package | File |
|---|---|---|
| `common/v1` (shared enums, DSSE envelope, key set) | `internal/contract` | `common.gen.go` (plus hand-written `Time`) |
| `event-schema/v1` | `internal/events` | `event.gen.go` |
| `adapter/v1` (definition, set) | `internal/adapters/registry` | `adapter.gen.go` |
| `policy/v1/bundle.schema.json` | `internal/bundle` | `bundle.gen.go` |
| `riskfeed/v1` | `internal/riskfeed` | `riskfeed.gen.go` |
| `rulepack/v1` (manifest, tests) | `internal/policy/rulepack` | `rulepack.gen.go` |
| `release/v1` | `internal/update` | `release.gen.go` |
| `detectorpack/v1` (manifest, detectors, set) | `internal/content` | `detectorpack.gen.go` |
| `communitypack/v1` | `internal/community` | `communitypack.gen.go` |

Policy files and rule files are the exception: `internal/policy/compiler` keeps hand-written types, because conditions accept a string or a list, and a test fails if those types and `policy.schema.json` drift apart.

Rules the generator follows: required fields are plain values; optional numbers, booleans and objects are pointers; optional strings, enums, slices and maps use `omitempty`; `oneOf` with `null` becomes a pointer; timestamps use `contract.Time`, which always encodes three fractional digits in UTC. `specs.DecodeInto` validates a document against its schema and decodes it strictly into a generated type. `TestRoundTrip` in `internal/contract` decodes every valid example strictly, re-encodes it, and requires the same, still-valid document.

## Checking

```bash
go test ./specs/          # every valid example passes, every invalid one fails
go test -v ./specs/       # also logs why each invalid example is rejected
```

The same run parses `privometry.cedarschema`, type-checks every compiled Cedar example against it (cedar-go's experimental validator; the Java bindings stay authoritative before signing), and runs the verdict vectors in `conformance/policy-verdicts/`.

Schemas reference each other with relative `$ref`s. Each schema's `$id` is `https://privometry.dev/specs/<path>`; the test fails if an `$id` does not match its file path. The host is a placeholder until the public spec site exists.

## Conventions

Contracts v1 "Shared conventions" apply. Choices made while writing the schemas:

- **DSSE field names follow the DSSE standard** (`payloadType`, `keyid`) rather than snake_case, so standard DSSE and Sigstore tooling can verify Privometry artifacts. Key IDs are `<role>:<name>:<16 hex of the key's SHA-256>`.
- **IDs are full ULIDs**: `<prefix>_` plus 26 Crockford base32 characters. The short IDs in the contracts document are abbreviations.
- **Timestamps** must be UTC with exactly three fractional digits.
- **Schemas stay open**: unknown fields are allowed so older consumers accept newer producers within v1. Enums are closed; new values are added in a minor release and consumers map unknown values to `other`.
- **YAML contracts** (policy, adapter, rule packs) are converted to JSON before validation. Timestamps keep their literal text, so YAML cannot reinterpret them.
- **Policy files are strict** (unknown keys are errors); machine-written contracts stay open.

## Cedar request rules

Every engine builds requests the same way (details in `policy/v1/privometry.cedarschema`):

- One request per command and target. `a && b`, or a command touching several paths, becomes several requests, and the strongest verdict wins.
- Every `Facts` attribute is always present, with an empty value when it does not apply, so compiled policies never need `has` checks.
- Values are normalized first: paths absolute with `/`, hosts lowercase, `program` as a base name, `subcommand` as up to four positional words.
- Exceptions and overrides are applied when a bundle is compiled; an expired exception is dropped at the next compile, and the daemon recompiles when one expires.
