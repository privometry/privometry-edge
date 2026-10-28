# communitypack/v1

## 1.0.0-draft.1 (2026-10-28)

- `communitypack.schema.json`: `privometry.communitypack/v1`, a rule pack (`kind: rules`) or detector pack (`kind: detectors`) published by someone other than Privometry, carried as the payload of a DSSE envelope with payload type `application/vnd.privometry.communitypack+json`. The document holds `id`, `version`, `published_at` and the pack folder as `files` (`pack.yaml`, `README.md`, `rules/*.yaml`, `tests/*.test.yaml` or `detectors/*.yaml`). The publisher `privometry` is not allowed.
- Signed by a key with the new role `publisher` (`common/v1`) whose name is the pack's publisher; a sensor accepts a pack only from a key its user trusted, runs the pack's own tests or samples, and refuses older versions.
- Examples: `example/helm-guard` (rules) and `example/service-tokens` (detectors), built from `rulepacks/community/` and `detectorpacks/community/` by `scripts/gen-conformance`; 7 invalid documents. Signature vectors: two valid packs, one signed by an unknown key, one signed by a release key.
