# Accounts: `privometry login` and `privometry console`

A person signs this machine up with their organization once, with `privometry login`. After that, `privometry console` signs them in to the console in the browser. Both speak the account API (`specs/account-api/v1`); enrollment speaks the edge API (`POST /edge/v1/enroll`).

## Signing up

```sh
privometry login --email meera@acme.example --create-org "Acme Payments" --slug acme
privometry login --email ravi@acme.example --invite 'https://console.privometry.dev/join#t=pit_...'
privometry login --email meera@acme.example --org acme
```

1. The account API emails a six-digit code. It answers the same whether or not the email, invitation or organization matches, so a mismatch only shows as a code that never arrives. Enter at the code prompt sends a new code.
2. Once the code is confirmed, the machine makes the person's **sign-in key** and asks for a PIN that unlocks it, twice. The key signs a proof over the server's challenge (a DSSE envelope over PAE, bound to the API's address, the registration and the key's SHA-256), and only the public key is sent.
3. The account API returns a one-time **enrollment token** bound to the person. The machine makes its **device key**, sends a certificate request with the token to `/edge/v1/enroll`, and keeps the certificate.

The CLI refuses an account API that answers for another address than the one it called (`--api`, or `PRIVOMETRY_ACCOUNT_API`), so it never signs a proof meant for another region. Requests go over HTTPS only and redirects are not followed.

## Two keys

| Key | Unlocked by | Used for |
|---|---|---|
| Sign-in key (`cli_key` credential) | The person's PIN | Signing in to the console. Ed25519 |
| Device key | Nothing: the daemon uses it unattended | Mutual TLS with the edge API (bundles, events, heartbeats, from M2). Ed25519 |

The sign-in key is sealed in software: AES-256-GCM under a key derived from the PIN with PBKDF2-HMAC-SHA256 (600,000 iterations), bound to its public key. Anyone who copies the sealed key can try PINs offline, so the account API is told its protection is `software`, and a passphrase is stronger than six digits. Keys held by the Secure Enclave or a TPM, which limit guesses in hardware, are not built yet.

The PIN never leaves the machine and cannot be recovered. If it is forgotten or the machine is lost, an admin resets the person in the console, which revokes their keys and emails a new invitation.

## Where things are kept

| What | Where |
|---|---|
| Sealed sign-in key, device key, organization hash key | The OS keychain under the service `dev.privometry`: the macOS login keychain (through `/usr/bin/security`) or the Secret Service on Linux (through `secret-tool`). Elsewhere, or with `--keystore file`, files in `<data dir>/keys/` readable only by the user |
| `account.json` | The account: API address, organization, user, role, credential ID, and which keystore holds the key. No secrets |
| `device.json` | The enrollment: device ID, region, edge API address, certificate and its expiry. No secrets |

Secrets reach the keychain tools on standard input, never on a command line. The data directory is `~/.privometry` (or `PRIVOMETRY_HOME`).

## Signing in to the console

```sh
privometry console          # asks for the PIN, then opens the browser
privometry console --print  # prints the link instead
```

The CLI asks the account API for a challenge, signs it with the sign-in key, and receives a one-time console link that works for 60 seconds. The link's token is in the URL fragment, so it never reaches server logs. Three wrong PINs end the command.

## Not yet

- Secure Enclave and TPM keys. On Windows the PIN prompt reads the console (`CONIN$` with echo off) and the sealed sign-in key is kept DPAPI-sealed; neither has run on a Windows machine yet.
- Finding a region from the organization slug (`GET /directory/{slug}` on the global tier); `--api` names it for now.
- The edge API does not exist on the platform yet (M2), so enrollment fails against it today and `privometry login` exits 1 after signing up. Run `privometry login --org SLUG --replace` once enrollment is live.
