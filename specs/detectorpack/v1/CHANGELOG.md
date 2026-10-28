# detectorpack/v1

## 1.0.0-draft.2 (2026-10-24)

- `pack-set.schema.json`: `privometry.detectorpack_set/v1`, Privometry's detector packs released together (PRD SCAN-09). DSSE payload type `application/vnd.privometry.detectorpacks+json`, signed with the release key. Each pack is its `pack.yaml` manifest and its detector files as JSON; `set_version` only increases.
- Devices use a set only when it is newer than the set built into them and every detector passes its own samples; a pack whose `min_sensor_version` is above the device's version stays at the built-in version.
- Examples: 1 valid and 5 invalid sets; signature vectors `detectorpacks-valid` and `detectorpacks-signed-by-feed-key`.

## 1.0.0-draft.1 (2026-10-23)

- `pack.schema.json`: `privometry.detectorpack/v1`, the `pack.yaml` of a detector pack, with the same fields, signing and trust model as rule packs (Contracts v1, Detector packs). `categories` are the six content-finding categories. The credential detector pack is `privometry/credentials`, distinct from the `privometry/secrets` rule pack.
- `detectors.schema.json`: `privometry.detectors/v1`, the files in `detectors/`. Each detector has an `id`, `title`, `category`, `kind` (`pattern`, `entropy`, `unicode`, `structure`), `severity`, `confidence`, `applies_to` sources, optional `keywords` prefilter and `allow` list, and inline `samples` (`match` and `no_match`, at least one each).
- Additions beyond Contracts v1:
  - `secret_type` (required for credentials) names the kind reported in `secret_detected`;
  - `injection_level` sets what injected and safety-weakening detectors contribute to `injection_detected`;
  - the named group `secret` marks the value to fingerprint, mask and test for entropy;
  - `min_length`, `unicode` classes (`zero_width`, `bidi_control`, `tag`, `variation_selector`, `private_use`) and `structure` shapes (`html_comment`, `base64_blob`, `hex_blob`, `whitespace_run`, `markdown_image_url`);
  - patterns are RE2 (no backreferences or lookaround) so Go and Java (re2j) agree;
  - samples may contain `{{}}`, removed before matching, so sample credentials are never contiguous in the repository.
- Examples: 2 valid and 2 invalid manifests, 1 valid and 11 invalid detector files.
