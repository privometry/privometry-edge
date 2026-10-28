# ADR-0003: A license problem never disables local protection

- Status: Accepted
- Date: 2026-10-23

## Context

Privometry is open core. Paid tiers add cloud sync, shared policy, approvals and governance, delivered to devices as signed entitlements inside policy bundles. Licenses expire, seats overflow, clocks drift and devices go offline. If any of these could switch off local enforcement, a billing event would become a security incident, and developers would lose trust in the free guard.

## Decision

1. Free features (`local_guard`, `scanner`, `local_timeline`, `community_feed`) never check entitlements.
2. When an organization's license expires after its grace period, devices keep enforcing the last signed policy bundle they verified. Only cloud-side actions pause: policy changes, new enrollments and, after notice, ingestion.
3. An expired or stale bundle raises a health finding; it is never discarded in favor of weaker rules.
4. Unknown feature keys are treated as `false`, which can only remove paid extras, never local enforcement.

## Consequences

- Entitlement checks live only around cloud-connected code paths (`internal/cloud/...`), never in the policy engine, hook client or timeline.
- Tests must cover expired, missing and tampered entitlements and show that local verdicts do not change.
- Revenue protection relies on the cloud, which already gates every paid feature, not on the device.
