# Migrating from Privo to Privometry

The repository and product namespaces were renamed together. This is intentionally a breaking rename rather than a compatibility alias.

| Legacy | Privometry |
| --- | --- |
| `github.com/privo/privo-oss` | `github.com/privometry/privometry-oss` |
| `privo` | `privometry` |
| `privod` | `privometryd` |
| `privo-hook` | `privometry-hook` |
| `privo-mcp-shim` | `privometry-mcp-shim` |
| `PRIVO_*` | `PRIVOMETRY_*` |
| `~/.privo` and `.privo/` | `~/.privometry` and `.privometry/` |
| `privo.*` schema names | `privometry.*` schema names |
| `application/vnd.privo.*` | `application/vnd.privometry.*` |

Existing local configuration and data are not moved automatically. Stop the legacy daemon before moving files, install the renamed daemon and hooks, and then run `privometry doctor`.

The signed-artifact media type is part of the DSSE signature input. Production policy bundles, entitlements, licenses, risk feeds, adapter sets, release manifests, and key-set envelopes issued with the legacy media types must therefore be reissued under the Privometry media types. The deterministic conformance fixtures in this repository have already been regenerated.
