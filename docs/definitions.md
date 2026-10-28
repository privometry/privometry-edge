# Signed definitions

Adapter definitions say where each coding agent keeps its config and memory files, how to install Privometry's hook and how to read and answer its hook payloads. Detector packs say what the content scanner looks for. Agents move files and rename fields more often than Privometry ships binaries, so both can be replaced at run time by a newer set signed with the release key (PRD EDGE-04, SCAN-09).

These sets hold Privometry's own definitions and packs. Packs from other publishers are separate: each is signed by its publisher's key and installed next to these, never in place of them; see `docs/community-packs.md`.

| Set | Built in | Signed payload | Payload type |
|---|---|---|---|
| Adapter definitions | `adapter-defs/*.yaml`, `adapterdefs.SetVersion` | `privometry.adapter_set/v1` | `application/vnd.privometry.adapters+json` |
| Detector packs | `detectorpacks/*/`, `detectorpacks.SetVersion` | `privometry.detectorpack_set/v1` | `application/vnd.privometry.detectorpacks+json` |

## Commands

```bash
privometry definitions status                  # which sets are in use, and why
privometry definitions update                  # download adapters.json and detectorpacks.json, verify, install
privometry definitions install adapters.json   # install a downloaded set (offline machines)
```

`update` downloads from the latest GitHub release's assets (`definitions.DefaultBaseURL`); `--url` or `PRIVOMETRY_DEFINITIONS_URL` point it at another folder, HTTPS only. Installed sets live in `~/.privometry/definitions/` (mode 0600). After an install the daemon service is restarted so it loads them; `--no-restart` skips that. `privometry doctor` reports the sets in use and warns when an installed set is ignored.

## When a set is used

`internal/definitions` loads the built-in set, then the installed one, and uses the installed set only when all of these hold:

1. The DSSE signature verifies against the `release` keys built into the binary (`internal/trust/keys/release-keys.json`). None ship yet, so every installed set is ignored until the release key exists.
2. The payload validates against its schema.
3. Its `set_version` is higher than the built-in set's. A binary upgrade whose built-in set is newer therefore ignores an old installed set, and installing refuses a set that is not newer than the built-in or installed one.
4. For adapters, the sensor is at least the set's `min_sensor_version`; every definition loads, and no agent is defined twice.
5. For detector packs, every pack compiles and every detector passes its own samples on this engine. A pack whose `min_sensor_version` is above the sensor's version stays at its built-in version; the rest of the set is used.

Otherwise the built-in set runs, and `status` names the reason. Development builds (`dev`) satisfy any `min_sensor_version`. The adapter set replaces all built-in definitions; the detector pack set replaces all built-in packs.

The hook client never loads definitions: it forwards payloads to the daemon, and its fail-mode matcher is built in. `guard install` uses the definitions in use, so if a signed set changes how hooks are registered, run `privometry guard install` again.

## Publishing a set

1. Change `adapter-defs/` or `detectorpacks/` and bump `SetVersion` in that folder's `embed.go`. `TestBuiltInSetVersionsArePinned` (in `internal/definitions`) pins each version's content digest, so it fails until you record the new digest. Without the bump, a set built from the old files could replace the new ones.
2. Build and sign both sets with the release key:

   ```bash
   go run ./scripts/sign-definitions -key release.seed -name prod -out dist/
   go run ./scripts/sign-definitions -out dist/    # unsigned payloads for an external or hardware signer
   ```

   The script checks each signed set as a sensor would (signature, schema, every definition, every sample) before writing it.
3. Attach `adapters.json` and `detectorpacks.json` to the release, next to `release.json`.

Sensors older than the new `SetVersion` pick the sets up with `privometry definitions update`; the sensor built from the same sources already has them built in.

## Known gaps

- No release key ships yet (an open item in `docs/implementation-plan.md`), so nothing signed is accepted today.
- Sets are installed on request; the daemon does not check for new ones on its own. With Team (P2), they arrive inside signed policy bundles.
- Release packaging does not attach the two sets yet.
