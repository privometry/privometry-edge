# Platform Integration

The Go edge communicates with the private Java platform through `specs/edge-api/v1`. The control plane, ingest service, processor, and MCP gateway must consume the same versioned contracts as the edge.

> Implementation status: the v1 contracts and generated Go message types exist, and `privometry login` registers people (account API) and enrolls devices (`/enroll`). Bundle synchronization, upload, heartbeat, approval, risk-feed and adapter-set clients are staged for later cloud milestones. This page defines the integration target and required security behavior; it does not imply that every client path is implemented today.

## Ownership boundary

| Capability | Go edge | Java platform |
| --- | --- | --- |
| Local scanning and enforcement | Owns | Observes aggregated/redacted state |
| Hook latency and fail modes | Owns | Must not be required |
| Local timeline | Owns | Receives permitted redacted events |
| Device enrollment and certificates | Client | Authority |
| Policy authoring and distribution | Verifies/applies | Authors/signs/distributes |
| Entitlement enforcement | Reads signed capabilities | Issues and meters |
| Billing and invoices | None | Separate billing domain |
| MCP gateway | Local shim | Hosted/self-hosted Java gateway |

## Edge API operations

The v1 API defines:

- `POST /enroll`
- `POST /certs:renew`
- `GET /bundle`
- `POST /events:batch`
- `POST /inventory`
- `POST /heartbeat`
- approval create/read operations
- `GET /riskfeed`
- `GET /adapters`

Use the OpenAPI operation IDs and message schemas as the source of truth. Do not create Java-only request shapes.

## Enrollment

1. The operator obtains a short-lived enrollment token from the control plane, or `privometry login` gets one bound to the person it registers (see below).
2. The edge generates a device key and certificate-signing request locally.
3. `/enroll` returns device identity, certificate material, endpoints, redaction/hash configuration, and the region's key set signed by a root key (`key_set`). A build with root keys verifies it; a build without pins it after checking it is signed by a root key it lists (`internal/cloud/keyset`).
4. Private device keys remain on the endpoint with restrictive permissions.
5. `/certs:renew` rotates certificates before expiry using authenticated device identity.

Enrollment or renewal failure must not disable local scanning, hooks, policy, or the timeline.

## Registration and console sign-in

People authenticate through `specs/account-api/v1`, separately from devices:

- `privometry login` verifies the person's email with a one-time code, generates their sign-in key, has them set a PIN that unlocks it, keeps it in the OS keychain (sealed with the PIN in software for now; Secure Enclave and TPM keys come later), and registers the public key. The response carries a one-time enrollment token bound to the person, which the edge uses with `/enroll` right after. The device key that enrolls has no PIN, because the daemon uses it unattended.
- People who never run the CLI register a passkey in the browser instead.
- `privometry console` signs a challenge with the sign-in key after the PIN and opens a one-time console link.
- The PIN never leaves the device; the platform stores public keys only.

## Policy bundles

The edge requests the current bundle and activates it only after:

- DSSE payload-type verification;
- Ed25519 signature verification by a trusted policy key;
- key-role and validity-window checks;
- schema validation;
- rollback/version checks;
- entitlement-envelope verification.

The platform answers 304 when the device already holds the newest bundle (`?current=<bundle_id>`). The edge retains the last verified bundle while offline, and keeps enforcing it after it expires.

What the edge does with a bundle (`internal/cloud/bundles`, `internal/policy.Sources`): the bundle's `sources` are the organization layer, loaded like policy files and merged with the built-in packs and the user and repo policies by `internal/policy/merge`. The bundle's own `cedar_policies` are what the platform compiled and validated for the organization layer alone, byte for byte what the Go compiler makes (`specs/conformance/policy-compile`). The organization's policies are managed through `specs/org-api/v1`; every change signs new bundles, one for the organization and one per workspace with policies of its own.

## Events and upload

Events use `event-schema/v1` and carry a per-device sequence. The edge batches events through `/events:batch`; the response acknowledges accepted/rejected counts and rejection categories.

What the sensor does (`internal/cloud/upload`): events wait in the timeline and go up in `device_seq` order from a cursor, so nothing recorded offline is lost (events older than 30 days are pruned locally). Before upload each event gets the enrolled organization and device, the person the device is enrolled for, and `user.local_user` as `hmac-sha256:<hex>` under the organization's hash key; the bundle's `privacy` upload levels and exclusions apply to `action.target` and `repo.remote`. Duplicates count as delivered and rejected events are never retried. The platform rejects events that are not from the device's certificate and events where its port of the redaction recognizers still finds a secret.

Integration requirements:

- redact before enqueueing or upload;
- preserve device ordering and idempotency;
- bound batches and offline storage;
- reject unknown or malformed schema versions explicitly;
- never log client certificates, raw commands, full paths, or unredacted payloads;
- apply retention by signed entitlement in the processor/storage tier.

## Inventory and heartbeat

Inventory snapshots describe agents, versions, MCP servers, hooks, policy state, and posture without secret values. Heartbeats report operational health, queue depth, version, hook state, and policy/bundle state. Heartbeat gaps are a platform finding, not a signal to disable the endpoint.

The daemon sends an inventory snapshot after enrolling, once a day and when a `rescan` command asks: agents with versions, their MCP servers (with the package or host they run), skills, plugins, other hooks and posture issues; never command lines, paths or values. The organization's catalog arrives in the bundle; the daemon gives each MCP call the catalog status the `privometry/mcp-allowlist` rules use (blocked, approved, unapproved, unknown), matching the server by name, package, URL or command from its last scan.

The daemon sends a heartbeat every 60 seconds (or as the response says) and applies `refresh_bundle` (fetch now) and `rescan` (rehash agent configs and memory files); it acknowledges them in the next heartbeat. Kill-switch commands are not supported by this sensor yet and stay unacknowledged.

## Approvals

An `ask` decision may be routed to the platform when organization policy enables remote approval. Approval requests are time-bounded and linked to a normalized action, rule IDs, device, user, and session. On timeout or connectivity failure, the edge follows the configured safe fallback; it does not silently allow.

Because a hook cannot wait for a person, the daemon answers a remotely routed ask with `deny` and a message at once, requests the approval in the background, and allows the next attempt of the same action in the same session once if it was approved (`docs/spikes/remote-approvals.md`). The bundle's `approvals` section says when to route: `all` asks, or `unattended` (sessions nobody is at, and agents that cannot ask).

## Risk feeds and adapters

Risk feeds and adapter sets are signed release artifacts. The edge validates sequence, publication time, minimum sensor version, schema, and signature role before replacing embedded data. A rejected update leaves the last valid or embedded set active.

An enrolled daemon fetches the risk feed hourly from `GET /edge/v1/riskfeed` (the curated feed when the bundle's entitlements include `curated_feed`, else the community feed), verified with the region's feed key from the pinned key set, and reports the sequence it holds in heartbeats. For an MCP server the organization's catalog does not list, a call takes the feed entry's `default_verdict` (`deny` from score 75, `ask` from 50), and a server whose live tool manifest matches none of the entry's `tool_manifest_hash` values is asked about; the event records `risk_score`. Catalog entries always win over the feed. The scoring methodology is in privometry-platform `docs/risk-methodology.md`.

## Leaked credentials

An enrolled device keys credential fingerprints in `content_finding` events with the organization's hash key from enrollment, so the same secret found on several devices has one fingerprint; fingerprints made before enrollment never leave the device. The platform groups them into credentials (org-api/v1 `credentials`, feature `credential_tracking`): devices, people, findings, sources and detectors per credential, and a status people set (`rotated`, `ignored`) that turns `still_present` when a device finds a rotated secret again. Never the secret or the path.

## Entitlements and licenses

The edge consumes capabilities and limits, not billing state. A self-hosted license is an offline signed artifact. Invalid or expired licensing can restrict paid synchronization, retention, or enterprise management features, but local protection continues.

Entitlements arrive signed with the license key in every bundle; a change of edition, period or seats signs new bundles (reason `entitlements_change`). When an organization is downgraded to free, its bundle turns `cloud_sync` off: the daemon stops uploading events and inventory, and the platform refuses them (and new enrollments) with `not-entitled`. Enrollment is also refused with `seat-limit-reached` when more developers were active than the organization has seats for longer than the seat grace period; devices already enrolled keep working. Editions, limits and grace periods are data in `specs/entitlements/v1/feature-registry.json`.

## Java integration checklist

- Generate Java types from the exact published schemas.
- Run all valid/invalid examples in platform CI.
- Run shared DSSE signature vectors against the Java verifier.
- Enforce mTLS and tenant context before message processing.
- Keep licensing checks out of local-protection decisions.
- Return stable machine-readable error types.
- Preserve unknown-event isolation so one rejected event does not poison a batch.
