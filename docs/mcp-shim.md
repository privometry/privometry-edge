# MCP shim

`privometry-mcp-shim` runs a local stdio MCP server in place of the agent that launches it and checks each tool call with the daemon before the server sees it (PRD EDGE-25). `privometry mcp wrap` writes it into agents' user-level MCP configs.

```bash
privometry mcp status            # every MCP server in your agents' user configs, wrapped or not
privometry mcp wrap --dry-run    # show the edits
privometry mcp wrap              # wrap each local stdio server; restart the agents afterwards
privometry mcp unwrap            # restore each server's own command
```

## What wrapping changes

A server such as

```toml
[mcp_servers.tickets]
command = "python3"
args = ["server.py"]
```

becomes

```toml
[mcp_servers.tickets]
command = "/path/to/privometry-mcp-shim"
args = ["--agent", "codex_cli", "--server", "tickets", "--", "python3", "server.py"]
```

Everything else about the server (environment, working folder, timeouts) stays. `unwrap` reads the original command back from the arguments after `--`. Wrapping twice changes nothing; wrapping after the shim moves points servers at the new path.

| Agent | File edited | Notes |
|---|---|---|
| Claude Code | `~/.claude.json` (`mcpServers` and each project's `mcpServers`) | Claude Code rewrites this file often: quit it before wrapping |
| Cursor | `~/.cursor/mcp.json` | Files with comments are refused rather than reformatted |
| Codex | `~/.codex/config.toml` | Edited line by line so comments and order survive; only the `command` and `args` lines of each `[mcp_servers.<name>]` table change, and the result is parsed to check nothing else did. Servers written as inline tables or dotted keys are reported and left alone. Comments inside an `args` array are not kept |

Remote servers (`url`, `type: http`) and repo configs (`.mcp.json`, `.cursor/mcp.json`, `.codex/config.toml` in a repo) are never edited. The first edit of a file keeps a copy at `<file>.privometry-backup`.

## What the shim does

The shim relays newline-delimited JSON-RPC both ways. Everything except the messages below passes through byte for byte: `initialize`, notifications, resources, prompts, and anything it cannot parse.

- **`tools/call`**: before forwarding, the shim sends the server, tool and arguments to the daemon (IPC operation `mcp`, phase `call`). The daemon decides it as an MCP action: the same rules, content scan of the arguments and timeline event as a hook call. An allowed call is forwarded unchanged. A denied call never reaches the server: the agent gets a tool result with `isError` set and Privometry's reason, which the model reads. MCP cannot ask the developer, so an `ask` verdict blocks the call and says so; allow trusted tools in `~/.privometry/policy.yaml`.
- **Tool results**: after forwarding a result to the agent, the shim reports it (phase `result`). The daemon scans it like hook tool output, marks the session when it carries injected instructions, and records findings. The result also marks the session as having seen untrusted input, unless a user or organization policy rule allows the server.
- **`tools/list` results**: reported after forwarding (phase `tools`). Each tool's name, description and input schema are scanned as model-facing text (detector source `tool_description`). A digest of the server's tool definitions is kept per agent and server; when a known server's tools change, an `integrity` event (check `other`) asks you to review the change.
- **Batches**: allowed calls in a batch are forwarded as a batch; denied ones are answered together.

Reports never delay the agent. Each tool call waits for the daemon for at most 2 seconds.

## When the agent's own hook decides

Claude Code, Cursor and Codex hooks all see MCP tool calls, so a call through the shim would otherwise be decided twice. When the agent that launched the shim has Privometry's hook installed and that hook has called the daemon within the last 7 days, the daemon leaves calls to the hook: the shim forwards them without a second decision or event, and only reports tool lists. An installed hook that never runs, such as a Codex hook not yet trusted in `/hooks`, does not count, so the shim enforces until it does. The last hook call per agent is kept in the timeline's state, so the mode survives daemon restarts.

Use the shim for agents without Privometry's hook, for MCP clients Privometry has no adapter for (`--agent other`), and everywhere to scan tool descriptions and catch servers whose tools change.

## When the daemon is down

The shim applies the fail modes as `privometry-hook` does (`hookclient.FailModeMCP`): the strongest of the `unapproved_mcp` mode, the `secrets` mode when the arguments carry a credential, and the categories the action falls in. `ask` becomes `deny`, `open` forwards the call. The decision is spooled as a `fail_mode` event for the daemon to import.

## Known gaps

- The session a shim reports is its own (`mcp-shim:<id>`), not the agent's, so injected text in a tool description or result marks the shim's session, not the agent's.
- Tool definitions are only seen when the agent lists them; a server that changes its tools mid-session without a `notifications/tools/list_changed` and a new `tools/list` is noticed at the next listing.
- On Windows the shim reaches the daemon over its named pipe and ends the server outright when the agent stops the shim (Windows has no polite stop signal for a console child). Not yet run on a Windows machine.
