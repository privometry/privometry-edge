# privometry/mcp-allowlist

Enforces your organization's MCP server catalog. Ships inside the Privometry sensor and is on by default, but does nothing until a catalog exists: on the Free tier every server's `catalog_status` is empty.

| Rule | Verdict | `catalog_status` |
|---|---|---|
| `blocked-server` | deny | `blocked` |
| `unapproved-server` | ask | `unapproved` (in the catalog, not approved yet) |
| `unknown-server` | ask | `unknown` (not in the catalog: shadow MCP) |

The catalog arrives in the organization's policy bundle (Team and above). Fail mode: `open`, logged, matching the proposed defaults; Enterprise organizations usually set `unapproved_mcp: closed`.
