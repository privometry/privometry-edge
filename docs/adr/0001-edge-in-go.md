# ADR-0001: Build the edge in Go

- Status: Accepted
- Date: 2026-10-23

## Context

The edge runs on every developer laptop as a CLI, a background daemon, a hook client that agents invoke on every tool call, and a stdio MCP shim. The hook client sits on the critical path: decision p95 must stay at or under 10 ms and cold start at or under 20 ms. The daemon must idle under 50 MB and 1% CPU, and the whole sensor must ship for macOS (Apple silicon and Intel), Linux (x86_64, arm64) and Windows 10 and 11.

## Decision

Write all edge binaries (`privometry`, `privometryd`, `privometry-hook`, `privometry-mcp-shim`) in Go, in the public `privometry-oss` repository.

## Consequences

- Static binaries with no runtime to install; `CGO_ENABLED=0` cross-compiles every target from one CI job.
- Fast process start suits a hook client that runs once per tool call.
- `cedar-go` gives an official, in-process policy engine (see ADR-0006).
- Pure-Go dependencies are preferred (for example `modernc.org/sqlite`) to keep cross-compilation free of cgo.
- The control plane and gateway are Java (ADR-0002), so shared behavior is pinned by language-neutral specs and conformance vectors that run in both repos.
