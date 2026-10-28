# rulepack/v1

## 1.0.0-draft.2 (2026-10-23)

- `ruletest.schema.json` facts gain `secret_detected`, `injection_detected`, `injection_seen`, `hidden_content` and `target_class`, so pack tests can exercise the content-scanning facts.

## 1.0.0-draft.1 (2026-10-23)

- `pack.schema.json`: the `pack.yaml` manifest from Contracts v1, plus optional `homepage` and `keywords`. Strict, like policy files.
- `rules.schema.json`: files in `rules/`, identified as `privometry.rules/v1` (new identifier; Contracts v1 did not name one). Each rule uses the policy-language rule definition; `locked` and `overridable` are rejected because they are organization-only.
- `ruletest.schema.json`: `privometry.ruletest/v1` test vectors as in Contracts v1, plus:
  - `covers`: the rule a test exercises. It counts as a match test when `expect.rule` names that rule, otherwise as a non-match test. This makes the "one matching and one non-matching test per rule" requirement checkable.
  - `expect.rule` omitted means no pack rule may match, so the unmatched default decides.
  - Facts are concrete values; `repo` selects a repo resource, otherwise the machine.
- Pack tests evaluate the pack alone with `unmatched: auto`.
- Checks done by the pack test runner (`go test ./rulepacks/`), not the schema: rule IDs unique across files, rule categories listed in the manifest, compiled Cedar type-checks, every test passes, coverage per rule, README present.
- Examples: 2 valid and 8 invalid manifests, 1 valid and 6 invalid rule files, 1 valid and 7 invalid test files. The first real pack is `rulepacks/core-catastrophic`.

## 1.0.0-draft.2 (2026-10-23)

- `expect.rules` (optional, additive): the exact set of deciding rules as qualified IDs; `[]` means no rule may match. Cannot be combined with `expect.rule`. Lets policy tests check pack rules, overrides and exceptions.
