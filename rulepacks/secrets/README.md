# privometry/secrets

Asks before an agent reads credentials. Ships inside the Privometry sensor and is on by default.

| Rule | Catches |
|---|---|
| `read-env-file` | `.env`, `.env.local`, `.env.production` (not `.env.example`, `.sample`, `.template`) |
| `read-ssh-key` | Private keys in `~/.ssh` (not `known_hosts`, `config` or `*.pub`) |
| `read-cloud-credentials` | `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker/config.json` |
| `read-credential-store` | Other stores: keychains, `.netrc`, `.npmrc`, `.git-credentials`, GitHub CLI token, GnuPG |
| `read-private-key-file` | `*.pem`, `*.key`, `*.p12`, `*.pfx`, Java keystores |
| `read-terraform-state` | `*.tfstate` |
| `read-credentials-file` | `credentials.json`, service-account keys, `secrets.yaml` |
| `dump-environment` | `env`, `printenv`, `set` |
| `secret-in-command` | A literal credential in a command (`secret_detected`), where it lands in history and transcripts |
| `secret-written-to-file` | A credential hardcoded into a file; `.env` and `.env.local` are exempt |
| `secret-in-mcp-arguments` | A credential passed to an MCP tool |

Every rule asks; the fail mode is `ask`. To block outright, override: `privometry/secrets:read-ssh-key: deny`. To allow one file for a while, add an exception with `target_path` and `expires_at`.

Facts come from the extractors: a read is a `secret_read` only when the file is a credential by name or location, so `cat README.md` never matches.
