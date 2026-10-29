# Release keys

Privometry trusts only the key set in `release-keys.json` in this folder,
embedded at build time, for everything signed with the `release` role:

- self-update manifests (`privometry update`, payload type
  `application/vnd.privometry.release+json`);
- adapter definition sets (`privometry definitions`, payload type
  `application/vnd.privometry.adapters+json`);
- Privometry's detector pack sets (`privometry definitions`, payload type
  `application/vnd.privometry.detectorpacks+json`).

The file is a `privometry.keyset/v1` document
(`specs/common/v1/keyset.schema.json`) holding one or more `release` keys.

It holds `release:gh-2026:fcb3791229626593` (created 2026-10-29), whose seed
is the `PRIVOMETRY_RELEASE_KEY` secret below. Every binary built since then
verifies releases, adapter definition sets and detector pack sets against it.
Tests that need a build without release keys call `trust.WithoutReleaseKeys`.

## Custody (decided 2026-10-28)

- **Release key**: an Ed25519 seed stored as the `PRIVOMETRY_RELEASE_KEY`
  secret of the GitHub `release` environment (its name in the
  `PRIVOMETRY_RELEASE_KEY_NAME` variable). Only the `sign` job of
  `.github/workflows/release.yml` reads it, on `v*` tags, after a required
  reviewer approves. It moves to a cloud key service later by rotation: make
  the new key, sign a release key set naming it with the root key, and point
  the workflow at it.
- **Root key**: an Ed25519 seed kept offline, in two places held by two
  people, never in CI or a cloud account. It signs key sets only.

To create the release key:

    go run ./scripts/release-keygen -role release -name gh-2026 -out <private folder>

Store the seed as the environment secret, delete the local copy once it is
in two safe places, and commit the printed `release-keys.json` here. Every
binary built after that commit verifies releases and definition sets signed
with it.

## Root keys

`root-keys.json`, when present, holds the `root` keys that sign each region's
key set (`application/vnd.privometry.keyset+json`). An enrolled device gets
its region's key set from `/edge/v1/enroll` and verifies it against these
keys; the key set names the `policy` key that signs bundles and the `license`
key that signs entitlements. Without `root-keys.json`, a device pins the key
set it gets at enrollment after checking that a root key listed in it signed
it, and `privometry device status` says so.

The offline root key `root:offline-a:25358486e189b3d3` exists (2026-10-29),
but its key set is not committed here yet. Today the control plane signs its
region key set itself at startup with `PRIVOMETRY_ROOT_KEY`, so a binary that
trusts only the offline key would refuse every control plane, and the only
way around that would put the offline seed online. First the control plane
must accept a key set signed ahead of time, offline, with the root key; then
`root-keys.json` can ship.

Never put test keys here: the conformance test keys have published seeds.
