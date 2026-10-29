# Privometry Developer Wiki

This wiki is the integration and maintenance guide for privometry-edge. It covers the local Go edge, agent hooks, policy engine, contract generation, signed artifacts, and the boundary with the Java platform.

## Choose a path

| Goal | Start here |
| --- | --- |
| Build and run Privometry locally | [Getting Started](Getting-Started.md) |
| Understand components and trust boundaries | [Architecture](Architecture.md) |
| Contribute to the Go repository | [Developer Setup](Developer-Setup.md) |
| Automate or operate the CLI | [CLI Reference](CLI-Reference.md) |
| Add or update an AI coding agent | [Agent Integration](Agent-Integration.md) |
| Author policies and rule packs | [Policy Integration](Policy-Integration.md) |
| Change schemas or generated types | [Contracts and Code Generation](Contracts-and-Code-Generation.md) |
| Connect the edge to the Java platform | [Platform Integration](Platform-Integration.md) |
| Build, test, and publish releases | [Testing and Release](Testing-and-Release.md) |
| Diagnose a broken installation | [Operations and Troubleshooting](Operations-and-Troubleshooting.md) |
| Review privacy and security guarantees | [Security and Privacy](Security-and-Privacy.md) |
| Look up project terminology | [Glossary](Glossary.md) |
| Publish repository docs to the GitHub wiki | [Publishing the Wiki](Publishing-the-Wiki.md) |

## Non-negotiable architecture rules

1. The endpoint edge is implemented in Go.
2. The control plane and MCP gateway are implemented in Java.
3. Licensing and billing are separate domains.
4. A license or cloud failure never disables local protection.
5. Untrusted data is validated and redacted before it crosses a trust boundary.
6. Contracts are versioned and generated artifacts are reproducible.

## Repository map

```text
cmd/              CLI, daemon, hook client, and MCP shim entry points
internal/         private Go implementation packages
adapter-defs/     data-driven agent discovery and hook definitions
rulepacks/        policy rules shipped with the edge
detectorpacks/    content detectors shipped with the edge
policies/         example repository and user policies
specs/            versioned public contracts and conformance vectors
ui/timeline-web/  embedded local timeline UI
test/             fixtures, end-to-end tests, and risky repositories
docs/             design notes, ADRs, and this wiki
```

## Documentation maintenance

Behavioral changes must update the relevant wiki page in the same pull request. Contract details in `specs/`, command help in `cmd/privometry`, and executable tests remain authoritative if documentation and code disagree.
