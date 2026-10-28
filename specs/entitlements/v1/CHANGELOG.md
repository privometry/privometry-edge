# entitlements/v1

## 1.0.0-draft.3 (2026-10-28)

- New feature key `credential_tracking` (trial, team, enterprise): leaked secrets tracked across devices with a rotation status (PRD SCAN-15, org-api/v1 `credentials`).

## 1.0.0-draft.2 (2026-10-28)

- `feature-registry.json` gains `editions` (PRD LIC-01: editions as data): each edition's default `limits`, `trial_days` (trial), `min_seats` (paid editions), `grace_days` after expiry, `seat_grace_days` for more active developers than seats, and `post_expiry_retention_days` after a downgrade. The platform takes limits and periods from here instead of code.
- New feature key `webhooks` (trial, team, enterprise): outbound webhooks (org-api/v1). Values: trial 14 days with 25 seats and 7 days of grace; Team from 5 seats, 90 days of retention, 15 days of grace; Enterprise per contract with 30 days of grace.
## 1.0.0-draft.1 (2026-10-23)

- `entitlements.schema.json` as in Contracts v1. Additions and constraints:
  - `valid_until` is null only for the free edition, which is always `active`;
  - `state: trial` requires `edition: trial`;
  - `key_id` must be a `license:` key.
- `license.schema.json`: the license file payload. `air_gapped` licenses must carry a `binding`; the free edition never has a license file.
- `feature-registry.json` (with `feature-registry.schema.json`): every feature key, the editions that include it, and whether it is local. Local features must include the free edition; `TestFeatureRegistry` checks that entitlement examples use registered keys and never switch a local feature off (ADR-0003). Extension keys use the `x_` prefix.
- Examples: 5 valid and 10 invalid entitlements, 2 valid and 5 invalid licenses.
