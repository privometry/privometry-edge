# account-api/v1

## 1.0.0-draft.5 (2026-10-28)

- One-time installation bootstrap for self-hosted (on-prem) control planes: `GET /bootstrap` reports `disabled`, `required` or `complete` and nothing else; `POST /bootstrap/challenges` takes the organization and the first owner (`BootstrapStart`) and returns a WebAuthn creation challenge (`BootstrapChallenge`); `POST /bootstrap/{bootstrap_id}:complete` takes the browser-created passkey (`RegistrationComplete`) and creates the organization, the owner, the `owner` membership, the passkey and a console session in one transaction. Both POSTs are authorized with the deployment's bootstrap token (security scheme `bootstrapToken`), which replaces email verification for this one organization only, works once, and is never used in SaaS. Like registration, they take no Idempotency-Key.
- Problem types `bootstrap-token-invalid` (401) and `bootstrap-unavailable` (409: bootstrap is disabled or already done). While bootstrap is enabled, `create_organization` registrations are refused.

## 1.0.0-draft.4 (2026-10-27)

- Enrollment tokens (PRD CP-04) for devices no person registers, such as an MDM rollout: `POST`, `GET /orgs/{org_id}/enrollment-tokens` and `DELETE /orgs/{org_id}/enrollment-tokens/{enrollment_token_id}`, for owners, admins and organization-wide admin API keys. A token has a number of uses (1 to 10,000), expires within 1 to 720 hours, and may put its devices in a workspace. The `pet_` secret is returned once; only its SHA-256 is stored.
- Devices: `GET /orgs/{org_id}/devices` (viewer and up; a workspace key sees only its workspace's devices) and `DELETE /orgs/{org_id}/devices/{device_id}`, which revokes the device's certificates at once. A member reset with `revoke_devices` now revokes the person's devices.
- New ID: `ent_` enrollment tokens.

## 1.0.0-draft.3 (2026-10-27)

- Organization API keys (PRD CP-02). `POST`, `GET /orgs/{org_id}/api-keys` and `DELETE /orgs/{org_id}/api-keys/{api_key_id}`, for signed-in owners and admins only. A key has a role (`admin`, `analyst` or `viewer`, never `owner`), may be limited to one workspace, and expires after 1 to 365 days (default 90). Its secret (`pak_` and 32 random bytes) is returned once, in `ApiKeyCreated`; only its SHA-256 is stored.
- Keys authenticate with `Authorization: Bearer` (security scheme `apiKey`) on the operations that list it: `GET /orgs/{org_id}/members` (new), invitations and member resets. They never manage keys, sessions or credentials. A workspace key sees only its workspace's members and cannot act on the whole organization.
- `GET /orgs/{org_id}/members` lists people with their organization-wide role and workspace roles (`MemberList`).
- New IDs: `apk_` API keys, `wsp_` workspaces. New problem type `api-key-invalid`.
- Examples: 17 (6 valid, 11 invalid) for `MemberList`, `ApiKeyCreate`, `ApiKey`, `ApiKeyCreated` and `ApiKeyList`.

## 1.0.0-draft.2 (2026-10-27)

- Problem types the first server (privometry-platform M1 step 2) needs, added to the list in `openapi.yaml`: `invalid-request` (the body does not match the contract; `errors` lists each field by JSON pointer), `registration-complete`, `key-registered` (the key is already registered in the organization), `not-signed-in`, `not-found` and `server-error`. A wrong code's problem carries `code_attempts_left`.

## 1.0.0-draft.1 (2026-10-27)

First draft of how people register and sign in to the console, after decision D1 (keys and a PIN set at registration; `privometry-platform/docs/implementation-plan.md`).

- A separate API from `/edge/v1`: people authenticate here with an email code, then a key; devices keep authenticating to `/edge/v1` with their certificate. Two operations are served by the global tier (`GET /regions`, `GET /directory/{slug}`), which knows only where each organization lives; everything else is served by the organization's home region.
- `openapi.yaml` (OpenAPI 3.1), 15 operations:
  - Registration: `POST /registrations` emails a six-digit code; `:resend`, `:verify` (returns the challenge) and `:complete` (registers the key) on `/registrations/{registration_id}`. Purposes: `create_organization` (the first person becomes owner), `accept_invitation`, `add_device`.
  - Sign-in: `POST /sign-in/challenges`, `POST /sign-in`, `POST /sign-in/links:redeem`, `POST /sign-out`.
  - Signed in: `GET /me`, `GET /me/credentials`, `DELETE /me/credentials/{credential_id}`, `POST /orgs/{org_id}/invitations`, `POST /orgs/{org_id}/members/{user_id}:reset` (recovery: revokes every credential, optionally the person's devices, and invites them again with their role).
- Two kinds of credential:
  - `cli_key`: the person's sign-in key. The CLI generates it in the OS keychain (`ES256` in the Secure Enclave or a TPM where available; `Ed25519` software keys as the fallback), the person sets a PIN that unlocks it, and the key signs a `Proof`. A CLI registration returns a one-time enrollment token bound to the person, so `privometry login` enrolls the device with `POST /edge/v1/enroll` right after. A CLI sign-in returns a one-time console link (token in the URL fragment, 60 seconds).
  - `webauthn`: a passkey created in the browser for people who never run the CLI. User verification (the computer's PIN or biometrics) and discoverable credentials are required; no attestation is requested. WebAuthn objects keep their camelCase JSON names.
- The PIN is never sent. The server stores public keys only.
- `Proof` is a DSSE envelope over PAE, with payload type `application/vnd.privometry.account-proof+json` and an `AccountProof` payload binding the purpose, the audience (the account API base URL), the challenge, and either the registration and key hash or the challenge and credential IDs. `keyid` is the key's SHA-256 when registering and the `credential_id` when signing in.
- Emails are checked by a loose pattern, not `format: email`: the Java validator rejects top-level domains missing from its list (for example `.example`), so Go and Java disagreed. `rulepack/v1` still uses `format: email` for maintainers.
- No account enumeration: `POST /registrations` answers 202 for every well-formed request.
- Limits written into the contract: the code is valid 10 minutes with 5 attempts and 3 resends, registrations expire after 30 minutes, challenges are single use for 5 minutes, sessions last at most 12 hours (cookie `__Host-privometry_session`: HttpOnly, Secure, SameSite=Strict).
- New IDs: `reg_` registrations, `crd_` credentials, `chl_` sign-in challenges, `ivt_` invitations. Secret tokens have prefixes secret scanners can match: `pit_` invitation tokens, `plt_` sign-in link tokens.
- Problem types under `https://privometry.dev/problems/`: invalid-code, registration-expired, slug-taken, already-member, add-device-disabled, proof-rejected, passkey-rejected, link-invalid, last-credential, not-allowed, rate-limited. Error bodies reuse the edge API's `Problem`.
- Examples: 82 (35 valid, 47 invalid) in `examples/<Message>/`. The CLI-key proofs and WebAuthn objects are real: made from TEST KEYS whose private halves are `sha256("privometry-test-key:account:<name>")` for `macbook-es256`, `linux-ed25519` and `passkey-es256`. `TestAccountProofs` verifies every CLI-key proof.
- `TestAccountAPI` applies the edge API's checks (operation list, unique IDs, problem+json errors, Retry-After) plus two of its own: registration and sign-in POSTs take no Idempotency-Key, since each code, challenge and link works once, while POSTs made with a session do; and the global tier's operations name their own server.
- Go types are generated into `internal/cloud/account`.
- Not in this draft: member listing, role changes and invitation management beyond creation (M1 console API); organization settings such as turning off `add_device`; hardware attestation of CLI keys (`protection` is reported, not verified); conformance vectors for proofs in `conformance/`.
- Server hosts under `api.privometry.dev` are placeholders.
