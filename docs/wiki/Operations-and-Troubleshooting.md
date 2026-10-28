# Operations and Troubleshooting

Start every investigation with:

```sh
privometry version
privometry doctor
privometry daemon status
privometry guard status
```

Use `--format json` for automation. Use `privometry doctor --bundle` only when a support archive is needed, and inspect it before sharing.

## Common problems

### Daemon not running

```sh
privometry daemon install
privometry daemon status
```

Inspect `~/.privometry/privometryd.log`. Verify the data directory is owned by the current user and inaccessible to group/others. On Linux, confirm a user systemd session exists; on macOS, confirm the launch agent is loaded in the current GUI user domain.

Hooks continue applying cached fail modes while the daemon is unavailable.

### Service file is out of date

Reinstalling rewrites and restarts the service:

```sh
privometry daemon install
```

This commonly occurs after replacing binaries or moving the installation directory.

### Hook installed but no events appear

1. Confirm the agent version is in the supported range.
2. Run `privometry guard status` and inspect the last-hook-call column.
3. For Codex, complete the `/hooks` trust step.
4. Restart the agent after configuration changes.
5. Run `privometry doctor` to exercise a synthetic hook decision.
6. Check for another installation path pointing at an older `privometry-hook`.

### Hook timeout

The hook-to-daemon budget defaults to 200 ms. A temporary development override is available through `PRIVOMETRY_HOOK_TIMEOUT_MS`, but increasing it is not a production fix. Investigate daemon load, blocked storage, policy size, content-scanning inputs, and endpoint security interference.

### Unix socket path too long

Set `PRIVOMETRY_HOME` to a shorter absolute directory and reinstall the daemon and hooks if necessary:

```sh
export PRIVOMETRY_HOME=/tmp/pv-$USER
privometry daemon install
```

Use a private persistent directory for real operation; `/tmp` is suitable only for isolated debugging.

### Insecure permissions

Privometry rejects symlinked, foreign-owned, or group/world-accessible security state. Correct ownership, remove symlinks, and restrict the directory:

```sh
chmod 700 ~/.privometry
chmod 600 ~/.privometry/*
```

Review the paths before running permission commands. Do not recursively change an unverified directory.

### Policy does not load

```sh
privometry policy test .privometry/policy.yaml
```

Check the schema identifier, qualified pack references, rule IDs, allowed facts, expiry timestamp format, and test directory. Policy parsing fails closed for the affected policy; fix the reported validation cause rather than removing validation.

### Unexpected deny or ask

Use an explanation command matching the operation:

```sh
privometry policy test --command "the command"
privometry policy test --read path/to/file
privometry policy test --fetch https://host/path --untrusted
```

Then query recent decisions with `privometry timeline --since 30m --format json`. Compare matching rule IDs and session state.

### Timeline unavailable

The CLI first asks the daemon, then falls back to opening `privometry.db` read-only. Check the data-directory override, permissions, and database existence. Do not repair or copy a live database without stopping the daemon.

### Update refused

Expected refusal reasons include development build, missing release trust keys, expired manifest, downgrade, wrong platform, digest/size mismatch, or invalid signature. Use the package manager or rebuild from source; never bypass verification.

## Safe reset sequence

For a development installation only:

1. `privometry guard uninstall`
2. `privometry daemon uninstall`
3. Back up the current data folder if timeline evidence matters.
4. Point `PRIVOMETRY_HOME` at a new empty private directory.
5. Reinstall daemon and guard.
6. Run `privometry doctor`.

Do not delete a production timeline or diagnostic evidence as a troubleshooting shortcut.

## Useful diagnostics

```sh
privometry scan --format json
privometry daemon status --format json
privometry guard status --format json
privometry doctor --format json
privometry timeline --since 24h --format json
```

Treat all diagnostic output as sensitive even when redacted.
