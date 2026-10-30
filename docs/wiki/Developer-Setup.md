# Developer Setup

## Toolchain

Required:

- Go 1.25+
- Git
- `make`

Recommended:

- `golangci-lint`
- `jq` for inspecting JSON reports and fixtures
- a JSON Schema-aware editor
- macOS or Linux for daemon and hook integration tests

## Clone and verify

```sh
git clone https://github.com/privometry/privometry-edge.git
cd privometry-edge
go version
make test
make check-generated
make build
```

Some tests open Unix and TCP loopback sockets or exercise launchd/systemd plans. Run them in an environment that permits local sockets. Service tests use fakes and should not modify the developer's actual service configuration.

## Make targets

| Target | Purpose |
| --- | --- |
| `make all` | Vet, test, and build |
| `make build` | Build four release binaries into `bin/` |
| `make test` | Run all Go tests |
| `make race` | Run tests with the race detector |
| `make lint` | Run `go vet` and `golangci-lint` when installed |
| `make fmt` | Format Go source with simplification |
| `make tidy` | Update module requirements |
| `make generate` | Regenerate Go contract types and signed vectors |
| `make check-generated` | Fail when generated Go types are stale |
| `make definitions` | Build the adapter and detector pack sets in `dist/`; `KEY=... NAME=...` signs them |
| `make hook-recorder` | Build the development-only hook payload recorder |
| `make clean` | Remove `bin/` and `dist/` |

## Package boundaries

- Code in `internal/` is private to this module.
- `pkg/edge` is the only public Go package. A connected build uses it to register a connector and its CLI commands, then runs the edge's own `privometry` and `privometryd`. Keep it small: add to it only what a connector needs.
- `adapter-defs`, `rulepacks`, `detectorpacks`, and `ui/timeline-web` embed release data.
- `specs/` is the public compatibility boundary and must remain language-neutral.
- CLI packages should coordinate components; business rules belong under `internal/`.
- OS-specific behavior belongs in `internal/platform` or files with Go build suffixes.

## Change workflows

### Change a contract

1. Edit the versioned schema and its changelog.
2. Add at least one valid and one invalid example.
3. Update semantic or OpenAPI tests.
4. Run `make generate`.
5. Run `make check-generated` and `make test`.
6. Coordinate the matching Java contract generation.

### Change policy behavior

1. Add facts or intent extraction tests.
2. Update compiler and engine tests.
3. Add rule-pack test cases.
4. Test an explanation through `privometry policy test`.
5. Document changes that affect policy authors.

### Change an adapter

1. Update `adapter-defs/<agent>.yaml`.
2. Add real but sanitized fixtures under `test/fixtures/`.
3. Validate paths, tool mappings, hook requests, and response templates.
4. Exercise guard install/uninstall round trips.

## Debug isolation

Never point experimental binaries at production user state. Use a temporary home:

```sh
export PRIVOMETRY_HOME="$(mktemp -d)"
./bin/privometryd
```

Use synthetic fixtures only. Raw hook payloads may contain source code, commands, paths, or secrets.

## Pull-request checklist

- Tests cover malformed and unavailable-dependency paths.
- Redaction occurs before persistence or upload.
- File and socket permissions remain user-only.
- Generated files are current.
- No secrets, databases, logs, or diagnostic archives are committed.
- Wiki, README, command help, and schemas agree.
