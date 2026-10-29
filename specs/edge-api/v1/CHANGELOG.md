# edge-api/v1

## 1.0.0-draft.9 (2026-10-28)

- Heartbeat hook `status` gains `disabled`: the hook is installed, but a setting turns the agent's hooks off or Privometry's own entry is turned off (adapter/v1 draft.7 `hooks.disable_settings`).

## 1.0.0-draft.8 (2026-10-28)

- `/enroll` is refused with `not-entitled` without the `cloud_sync` feature and with `seat-limit-reached` after a seat overage outlasts its grace period; `/events:batch` and `/inventory` are refused with `not-entitled` without `cloud_sync`, and devices stop uploading until a bundle turns it back on.
## 1.0.0-draft.7 (2026-10-28)

- `/approvals` describes the flow that fits the hook budget: deny at once with a message, request the approval in the background, allow the next attempt once if it is approved (privometry-edge `docs/spikes/remote-approvals.md`).
## 1.0.0-draft.6 (2026-10-28)

- `/inventory` says when the sensor sends a snapshot and what items carry; inventory items gain `package` and `host` (event-schema/v1 draft.3).
## 1.0.0-draft.5 (2026-10-28)

- `/events:batch` says what the sensor sets before upload (`org_id`, `device.device_id`, `user.user_id`, and `user.local_user` as `hmac-sha256:<hex>` under the organization's hash key) and lists the problem types of rejected events: `event-invalid`, `event-not-from-device`, `secret-detected`.
- `/heartbeat` says what the server records and that it sends `refresh_bundle` until the device reports the newest bundle.
## 1.0.0-draft.4 (2026-10-28)

- `EnrollResponse.key_set` (optional, additive): the region's key set signed by a root key, a DSSE envelope with payloadType `application/vnd.privometry.keyset+json`. It names the policy key bundles are signed with and the license key entitlements are signed with. A sensor with root keys built in verifies it against them; a sensor without (no root key is decided yet) pins it at enrollment after checking it is signed by one of its own root keys, and says so in `privometry device status`.
- `/bundle` describes which bundle a device gets (its workspace's when the workspace has policies of its own, else the organization's; one version sequence for both), re-signing near expiry, and what the device checks before it uses a bundle.
## 1.0.0-draft.3 (2026-10-27)

- `/enroll` describes the certificate it returns: for the CSR's key, 30 days, client authentication only, subject CN the `device_id`, URI SANs `urn:privometry:device:<device_id>` and `urn:privometry:org:<org_id>`, and the chain leaf then device CA. A retry with the same token and CSR key returns the same device after the token's last use.

## 1.0.0-draft.2 (2026-10-27)

- Enrollment tokens can come from `account-api/v1`: when `privometry login` registers a person, `POST /account/v1/registrations/{registration_id}:complete` returns a one-time token bound to that person, valid 10 minutes, and the CLI enrolls the device with it. `/enroll` itself is unchanged; only the descriptions of `enrollment_token` and `user_id` say so.

## 1.0.0-draft.1 (2026-10-23)

- `openapi.yaml` (OpenAPI 3.1) for the nine endpoints of Contracts v1: enroll, certificate renewal, bundle, event batches, inventory, heartbeat, approvals (create and long-poll), risk feed and adapters.
- Bodies live in `messages.schema.json` as plain JSON Schema, so they are validated like every other contract; each has examples in `examples/<Message>/`.
- Additions beyond Contracts v1:
  - Enrollment returns an organization `hash_key` (HMAC key for hashed privacy levels); the bundle carries the organization's `privacy` settings.
  - Heartbeat reports `keyset_version`, `active_stops` and `acked_commands`; commands repeat until acknowledged and have `cmd_` IDs.
  - Hook status adds `untrusted` for Codex hooks the user has not approved yet.
  - Inventory snapshots use the event schema's inventory item and get an `inv_` receipt ID.
  - Rejected events in a batch carry a problem `type` and are not retried.
- Security: `mutualTLS` everywhere except enrollment (bearer enrollment token), the community risk feed and adapters (public).
- `TestEdgeAPI` checks the operation list, unique operation IDs, Idempotency-Key on every POST, problem+json on every error, Retry-After on 429, and that every `$ref` resolves and compiles. It is not a full OpenAPI validator.
- Server host `api.privometry.dev` is a placeholder.
