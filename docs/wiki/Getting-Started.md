# Getting Started

This guide builds Privometry from source and connects it to a supported local coding agent.

## Prerequisites

- Go 1.25 or newer
- Git
- macOS, Linux or Windows 10/11 for daemon service installation
- At least one supported agent: Claude Code `>=2.1.295 <3.0.0`, Codex `>=0.14.0 <1.0.0`, Cursor `>=1.7.0 <3.0.0`, Gemini CLI `>=0.26.0 <1.0.0`, Copilot CLI `>=1.0.0 <2.0.0` or Antigravity `>=1.1.21 <2.0.0`

On Windows the daemon runs from a per-user Task Scheduler logon task and listens on a named pipe; see `docs/daemon.md`. Windows support is tested in CI and with simulated Windows environments, not yet on a Windows machine.

## Build

```sh
git clone https://github.com/privometry/privometry-oss.git
cd privometry-oss
make test
make build
```

The build produces:

```text
bin/privometry
bin/privometryd
bin/privometry-hook
bin/privometry-mcp-shim
```

Keep the first three binaries in the same directory. The CLI uses sibling discovery when installing the daemon and hooks.

## Inspect before changing anything

```sh
./bin/privometry scan
./bin/privometry daemon install --dry-run --privometryd ./bin/privometryd
./bin/privometry guard install --dry-run --hook ./bin/privometry-hook
```

`scan` is read-only. The two dry runs show the service and agent-configuration changes that would be made.

## Install local protection

```sh
./bin/privometry daemon install --privometryd ./bin/privometryd
./bin/privometry guard install --hook ./bin/privometry-hook
./bin/privometry doctor
```

For Codex, follow the trust instructions printed by `guard install`; the hook is not active until the agent trusts it.

## Verify an action

Use a synthetic decision before running a real agent:

```sh
./bin/privometry policy test --command "rm -rf ~/old"
./bin/privometry policy test --read .env
```

Then invoke a tool in the configured agent and inspect the result:

```sh
./bin/privometry guard status
./bin/privometry daemon status
./bin/privometry timeline --limit 10
```

## Add repository policy

Create `.privometry/policy.yaml` in the repository. Start from `policies/examples/web-app/policy.yaml`, then test it before committing:

```sh
mkdir -p .privometry/tests
cp policies/examples/web-app/policy.yaml .privometry/policy.yaml
cp policies/examples/web-app/tests/policy.test.yaml .privometry/tests/policy.test.yaml
./bin/privometry policy test .privometry/policy.yaml
```

User-level overrides live at `~/.privometry/policy.yaml`. Organization policy arrives as a signed bundle and is not editable locally.

## Local files

By default, runtime state is stored under `~/.privometry/`:

- `privometry.db`: redacted timeline database
- `privometryd.sock`: user-only daemon IPC socket
- `privometryd.lock`: single-instance lock
- `privometryd.log`: daemon log
- `failmodes.json`: hook fallback decisions
- `spool.jsonl`: events buffered while the daemon is unavailable
- `policy.yaml`: optional user policy

Set `PRIVOMETRY_HOME` to use a different data directory, including for isolated development environments.

## Remove the integration

```sh
./bin/privometry guard uninstall
./bin/privometry daemon uninstall
```

Uninstalling the daemon first leaves hooks applying their built-in fail modes. Removing the guard unregisters Privometry while preserving unrelated hooks.

## Next steps

- [CLI Reference](CLI-Reference.md)
- [Policy Integration](Policy-Integration.md)
- [Agent Integration](Agent-Integration.md)
- [Operations and Troubleshooting](Operations-and-Troubleshooting.md)
