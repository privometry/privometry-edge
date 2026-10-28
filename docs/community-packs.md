# Community packs

Rule packs and detector packs published by someone other than Privometry (PRD EDGE-21). A publisher signs each pack with their own key; a person decides which publishers to trust; the sensor checks every pack again each time it loads.

## For people installing packs

```bash
privometry trust add acme.keyset.json      # shows the publisher, key ID and fingerprint, then asks
privometry packs install https://packs.acme.example/acme-k8s-guard-1.2.0.pack.json
privometry packs list                       # each pack, and why it does not load if it does not
privometry trust list
privometry packs remove acme/k8s-guard
privometry trust remove acme                # every pack acme signed stops loading
```

- **Rule packs** apply only where a policy opts in: `extends: [acme/k8s-guard@^1]` in `~/.privometry/policy.yaml`, a repo's `.privometry/policy.yaml`, or an organization policy. They sit in the built-in layer, so user, repo and organization rules can override them, and strongest verdict still wins.
- **Detector packs** run with Privometry's detectors as soon as they are installed and feed the same content facts (`secret_detected`, `injection_detected` and so on). An allowlist entry can silence one of their detectors by its ID, such as `acme/internal-tokens:service-token`.
- `install` restarts `privometryd` when it runs as a service, so it loads the pack; `--no-restart` skips that.
- Compare the fingerprint `trust add` shows with one the publisher announced somewhere you trust (their website, a signed release note). `--yes` skips the question for scripts that checked it another way.

## What the sensor checks

At install:

1. The envelope is DSSE with payload type `application/vnd.privometry.communitypack+json`.
2. It is signed by a trusted key of the pack's own publisher: `publisher:acme:…` may sign `acme/*` and nothing else, so a trusted key from one publisher cannot ship packs under another's name. The publisher `privometry` is reserved; Privometry's own packs come built in or in sets signed by the release key (`docs/definitions.md`).
3. The payload is a valid `privometry.communitypack/v1` document: only `pack.yaml`, `README.md`, `rules/*.yaml`, `tests/*.test.yaml` or `detectors/*.yaml`, each path once.
4. `pack.yaml` has the same ID and version as the envelope and a `min_sensor_version` this sensor meets.
5. The pack passes its own release gate: a rule pack's tests with the same checks as `privometry policy test` (schemas, Cedar type-check, categories, a matching and a non-matching test per rule), or every detector's samples.
6. The version is newer than the one installed. Going back means `packs remove` first.

At every load (daemon start, CLI commands): steps 1 to 4 again, with the keys trusted now and their validity windows. A pack whose key was removed or expired, or whose file changed, is left out with a warning, and `packs list` says why.

Files live in `~/.privometry/community/` (or `%LOCALAPPDATA%\Privometry\community`): `trust.json` and `packs/<publisher>/<name>.json`, the signed envelope as received.

## For publishers

```bash
privometry packs keygen --publisher acme           # acme.key (secret) and acme.keyset.json (share it)
privometry packs sign ./k8s-guard --key acme.key   # runs the pack's checks, writes acme-k8s-guard-1.2.0.pack.json
```

Start from `rulepacks/community/example-helm-guard/` or `detectorpacks/community/example-tokens/`. Pack IDs are `<publisher>/<name>`; the publisher part must be the name in your key. Raising the version is how an update reaches people: a stricter verdict is a minor change, and removing or loosening a rule is a major one, so people who wrote `@^1` are not surprised.

To rotate a key, generate a new one, publish a key set holding both, sign new versions with the new key, and ask people to `trust remove` the old key ID once your packs are re-signed.

## Not yet

- No revocation list: a leaked publisher key stays trusted until each person removes it.
- No registry or search; packs are shared as files or URLs.
- The organization layer cannot push community packs to devices yet (P3); each device installs its own.
- Keys sign with Ed25519 seeds in a file; hardware keys are not supported.
