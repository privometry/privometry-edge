# org-api/v1

## 1.0.0-draft.10 (2026-10-30)

- Integrations: connecting the GitHub App needs `authorization_code`, the OAuth code GitHub returns once the person connecting authorizes the app (the app requests it during installation). The installation connects only when GitHub lists it among the installations that person can see, so an installation ID, which is a small public number, no longer connects another organization's repositories. The code is used once and never stored or returned; other tools refuse it.
- Problem types: `installation-not-authorized` (403), `authorization-code-refused` (400).

## 1.0.0-draft.9 (2026-10-28)

- Webhook secret rotation: `POST /orgs/{org_id}/webhooks/{webhook_id}:rotate-secret` returns a new `whsec_` secret once. The previous secret keeps signing deliveries for `previous_secret_hours` (default 24, at most 168, 0 for none), so `webhook-signature` then carries two signatures, the new secret's first; `Webhook.previous_secret_expires_at` says until when.
- Deliveries connect to the address the destination check approved, so a host name that resolves differently a moment later (DNS rebinding) cannot redirect them. TLS still verifies the certificate against the URL's host.
- Integrations: a Jira `config.base_url` and a Teams Workflows URL (`secret`) are checked like webhook URLs: https, no credentials, public addresses only. They are refused with `invalid-request` when saved, and calls to them go to the address checked.

## 1.0.0-draft.8 (2026-10-28)

- Credentials (PRD SCAN-15): `GET /orgs/{org_id}/credentials` (leaked secrets tracked across devices by their organization-keyed fingerprint, with devices, people, findings, sources, detectors and a status), `GET /orgs/{org_id}/credentials/{credential_id}` (with each device that found it) and `POST /orgs/{org_id}/credentials/{credential_id}:mark` (rotated, ignored, or exposed again). Statuses: `exposed`, `rotated`, `still_present` (marked rotated, then found again) and `ignored`. `credential_id` is derived from the fingerprint. Needs the `credential_tracking` feature. Never the secret or a path.

## 1.0.0-draft.7 (2026-10-28)

- Licensing (PRD LIC-01 to LIC-05, LIC-10): `GET /orgs/{org_id}/license` (edition, state, features, limits, grace, seats as active developers with overage and its grace, subscription, offers) and `GET /orgs/{org_id}/license/events` (every license change and enforcement action).
- Billing (CP-30): `POST /orgs/{org_id}/billing:checkout`, `:seats` and `:cancel` (owners, signed in), `GET /orgs/{org_id}/billing/invoices` and `POST .../{invoice_id}:download`. Razorpay takes INR and Paddle USD; billing confirms payments and issues invoices, entitlements decide features.
- Features are checked by key: changes that need a feature the organization lacks are refused with `not-entitled`; reading what it has is never refused.
- Problem types: `not-entitled`, `subscription-exists`, `no-subscription`, `billing-unavailable`.
- Bundles gain the reason `entitlements_change`. Webhooks need the `webhooks` feature.
- New IDs: `lev_` license events, `ivc_` invoices.
## 1.0.0-draft.6 (2026-10-28)

- Webhooks (PRD CP-29): `GET`, `POST /orgs/{org_id}/webhooks`, `PUT`, `DELETE .../{webhook_id}`, `POST .../{webhook_id}:test` and `GET .../{webhook_id}/deliveries`. Topics: `finding.opened`, `finding.updated`, `finding.resolved`, `policy.published`, `policy.archived`, `inventory.component_discovered`, `event.asked`, `event.denied`, `approval.requested`, `approval.decided`. Deliveries (`WebhookEvent`, described in the top-level `webhooks` section) are signed as Standard Webhooks specify with a `whsec_` secret shown once, retried for about a day, and disable a webhook whose delivery failed every retry with nothing delivered since.
- Overview (CP-28): `GET /orgs/{org_id}/overview` counts devices, the last day's actions by verdict (and per minute for the last hour), open findings by severity, components and shadow AI, and pending approvals, for the console's dashboard.
- Inventory components gain `risk_score` and `risk_level` from the published risk feed entry for their package.
- The organization API is the public REST API (CP-29): every operation that lists `apiKey` works with an organization API key.
- New IDs: `whk_` webhooks, `whd_` deliveries, `whe_` webhook events.
## 1.0.0-draft.5 (2026-10-28)

- Approvals (PRD CP-21, INT-02): `GET`, `PUT /orgs/{org_id}/approval-settings` (enabled, route, timeout, the Slack or Teams integration; changes sign a bundle), `GET /orgs/{org_id}/approvals` and `POST /orgs/{org_id}/approvals/{approval_id}:decide` (console decisions, as Teams cards link to). Slack decides with message buttons.
- Integrations add `slack` (bot token in `secret`, the app's `signing_secret`, `channel_id`) and `teams` (a Workflows webhook URL in `secret`).
## 1.0.0-draft.4 (2026-10-28)

- Findings (PRD CP-15 basic): `GET /orgs/{org_id}/findings` and `POST /orgs/{org_id}/findings/{finding_id}:triage` (status `open`, `in_progress`, `resolved`, `accepted`; owner; comment). Findings come from posture issues in inventory snapshots, missing or modified hooks in heartbeats and integrity events (tamper), and devices without a heartbeat for a day (health). A repeat of an open finding updates it, a cleared condition resolves it (`resolution: auto`), and an accepted finding stays accepted.
- Integrations (CP-16, INT-01, INT-03): `GET`, `POST /orgs/{org_id}/integrations` and `DELETE .../{integration_id}` for Jira, Linear and the Privometry GitHub App. Secrets are kept encrypted and never returned; Jira and Linear get a `webhook_url` and a one-time `webhook_secret`, so ticket changes come back (two-way sync). GitLab is not offered.
- New IDs: `fnd_` findings, `int_` integrations.
## 1.0.0-draft.3 (2026-10-28)

- Inventory (PRD CP-07, CP-09): `GET /orgs/{org_id}/inventory/components` (agents, MCP servers, skills, plugins, hooks and IDE extensions on the organization's devices, with device and installation counts and catalog status; `catalog_status=unknown` is shadow AI) and `GET /orgs/{org_id}/inventory/agents` (each agent on each device, with what it can reach).
- Catalog: `GET`, `POST /orgs/{org_id}/catalog` and `DELETE /orgs/{org_id}/catalog/{catalog_entry_id}`: approved and blocked components, matched by kind and name, or by package or URL glob; command globs are checked on devices only. Changes sign a new bundle, whose `catalog` devices use for `catalog_status`.
- Catalog status, as the `privometry/mcp-allowlist` rules expect: `blocked` or `approved` when an entry matches (approved only for its listed versions); `unapproved` when the component is in the catalog but not approved for its version; `unknown` when it is not in the catalog: shadow AI. Devices leave `catalog_status` empty when the catalog lists nothing of that kind, so the rules stay quiet until an organization starts a catalog.
- New IDs: `cmp_` components, `agi_` agent instances, `cat_` catalog entries.
## 1.0.0-draft.2 (2026-10-28)

- Event search (PRD CP-06): `GET /orgs/{org_id}/events` with filters (type, device, session, verdict, rule, agent, time range), newest first, up to 500 per page with an opaque `next_cursor` (`EventPage`). Events are returned as stored in the cloud: redacted, local usernames hashed. A workspace API key sees its workspace's devices' events.
## 1.0.0-draft.1 (2026-10-28)

First draft of the organization API (`/api/v1`): what an organization manages from the console (session cookie) or with an organization API key (both from `account-api/v1`). Later milestones add their resources here.

- Policies (PRD CP-10, CP-11, CP-12): create from YAML, list, get, archive; every change is a new immutable version (`POST .../versions` with `base_version`, refused with `version-conflict` when the policy moved on); list and get versions; `GET .../diff?from=&to=` (unified diff of the YAML plus rule IDs added, removed and changed); `:rollback` makes a new version with an earlier one's content. `POST /orgs/{org_id}/policies:check` validates and compiles without saving.
- Scopes: the organization, or one workspace. Repo-level scope is a rule's `when.repo`.
- Monitor mode: a rule's `mode` (or `defaults.mode`); `Policy.monitor_rule_count` shows how many rules are still in monitor.
- Bundles (CP-14): every policy change signs new bundles (one for the organization and one per workspace with policies of its own, one version sequence); `GET /orgs/{org_id}/bundles` lists them and `POST` signs new ones on demand.
- Problem types: `invalid-request`, `not-signed-in`, `api-key-invalid`, `not-allowed`, `not-found`, `version-conflict`, `policy-name-taken`, `policy-name-changed`, `policy-archived`, `policy-invalid` (422, `errors` by JSON pointer into the YAML), `rate-limited`, `server-error`.
- Examples: 48 (24 valid, 24 invalid) for 13 messages.
