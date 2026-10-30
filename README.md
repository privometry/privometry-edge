# Privometry Edge

**Local-first security guardrails for AI coding agents.**
Privometry Edge helps developers discover agent configurations, evaluate
supported tool events against policies, scan content for secrets and
prompt-injection signals, and investigate a redacted local activity timeline.

- [Privometry website](https://www.privometry.com/)
- [Developer documentation](https://github.com/privometry/privometry-edge/wiki)
- [Agent integrations and current behavior](https://github.com/privometry/privometry-edge/wiki/Agent-Integration)
- [Security and privacy](https://github.com/privometry/privometry-edge/wiki/Security-and-Privacy)

Local protection does not depend on a cloud connection or a valid commercial license.

## What is included

- `privometry`: operator CLI for scanning, guard installation, policy testing, timelines, diagnostics, and updates.
- `privometryd`: per-user daemon that evaluates hook events and stores the local timeline.
- `privometry-hook`: latency-sensitive hook client invoked by supported coding agents.
- `privometry-mcp-shim`: local stdio MCP wrapper that checks each tool call with the daemon before the server sees it and scans tool descriptions; `privometry mcp wrap` installs it into user-level MCP configs. See [MCP shim](docs/mcp-shim.md).
- Versioned JSON Schema, OpenAPI, Cedar, policy, rule-pack, detector-pack, and signed-artifact contracts under `specs/`.

Supported adapter definitions currently ship for Claude Code, Codex, Cursor, Gemini CLI, Copilot CLI and Antigravity. Hook coverage and fail-open/fail-closed behavior differ per agent; see [Agent integration](docs/wiki/Agent-Integration.md), and the website's [Claude Code security](https://www.privometry.com/agents/claude-code/) and [MCP security](https://www.privometry.com/product/mcp-security/) overviews. The data-driven adapter format allows additional agents to be added without changing the core policy engine.

## Build from source

Prerequisites: Go 1.25 or newer, Git, and macOS, Linux or Windows 10/11.

```sh
git clone https://github.com/privometry/privometry-edge.git
cd privometry-edge
make test
make build
```

The four binaries are written to `bin/`.

## First local integration

```sh
./bin/privometry scan
./bin/privometry daemon install --privometryd ./bin/privometryd
./bin/privometry guard install --hook ./bin/privometry-hook
./bin/privometry doctor
./bin/privometry timeline
```

Use `--dry-run` with daemon and guard installation when evaluating the changes first.

## Documentation

The developer wiki starts at [`docs/wiki/Home.md`](docs/wiki/Home.md). Useful entry points:

- [Getting started](docs/wiki/Getting-Started.md)
- [Architecture](docs/wiki/Architecture.md)
- [Developer setup](docs/wiki/Developer-Setup.md)
- [CLI reference](docs/wiki/CLI-Reference.md)
- [Agent integration](docs/wiki/Agent-Integration.md)
- [Policy integration](docs/wiki/Policy-Integration.md)
- [Contracts and code generation](docs/wiki/Contracts-and-Code-Generation.md)
- [Platform and event integration](docs/wiki/Platform-Integration.md)
- [Operations and troubleshooting](docs/wiki/Operations-and-Troubleshooting.md)

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Report suspected vulnerabilities using the process in [SECURITY.md](SECURITY.md), not a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
