# release/v1

## 1.0.0-draft.1 (2026-10-23)

- `release.schema.json`: `privometry.release/v1`, one release on one channel (`stable` or `beta`) with a download per OS and architecture.
- Signed as DSSE with payload type `application/vnd.privometry.release+json` by a `release` key from the key set.
- `expires_at` is required, so a stale manifest cannot be replayed indefinitely; each artifact has an exact `size` and `sha256`, an HTTPS `url`, and the list of `binaries` the archive may contain (nothing else is extracted).
- Examples: 2 valid, 8 invalid.
