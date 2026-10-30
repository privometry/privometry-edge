# Built-in Rules

The edge ships with 45 rules in five packs, embedded from `rulepacks/`. They apply on every device, with or without an organization bundle, and they keep working offline.

| Pack | Version | Rules |
| --- | --- | --- |
| `privometry/agent-instructions` | 1.0.0 | 4 |
| `privometry/core-catastrophic` | 1.0.0 | 17 |
| `privometry/exfiltration` | 1.1.0 | 10 |
| `privometry/mcp-allowlist` | 1.0.0 | 3 |
| `privometry/secrets` | 1.1.0 | 11 |

Each rule has one of two verdicts:

- **Deny** blocks the action, and the agent sees the rule's message.
- **Ask** pauses the action until the developer confirms it.

A rule is referred to by its qualified ID, `<pack>:<rule>`, for example `privometry/secrets:read-env-file`. Rule files under `rulepacks/<pack>/rules/` are authoritative if this page and the code disagree.

## Rule reference

| S.No | Pack | Rule ID | Verdict | What it matches | Harm if the rule did not exist |
| --- | --- | --- | --- | --- | --- |
| 1 | agent-instructions | `ask-instruction-edit` | Ask | An agent editing its own instruction files (CLAUDE.md, AGENTS.md, rules folders). Agents' automatic memory folders are left alone, except after an injection. | An agent can quietly change the rules every later session follows, such as "always auto-approve" or "push straight to main". |
| 2 | agent-instructions | `block-memory-edit-after-injection` | Deny | Memory or instruction edits after the session read content flagged as injected instructions. | A one-time prompt injection becomes permanent and re-infects every future session. |
| 3 | agent-instructions | `ask-safety-weakening-write` | Ask | Writing text that tells agents to skip approvals, switch off hooks or ignore earlier instructions, into any file. | Planted text in a file can switch off safety checks for the next agent that reads it. |
| 4 | agent-instructions | `ask-hidden-content-write` | Ask | Writing text a reviewer would not see, such as invisible characters or instructions in HTML comments. | Hidden instructions get through code review and later steer agents or people. |
| 5 | core-catastrophic | `db-drop` | Deny | Dropping a database, schema or table, detected from SQL, CLIs and ORM commands. | Data is lost in one command, and getting it back depends on backups. |
| 6 | core-catastrophic | `home-recursive-delete` | Deny | Recursive deletes in the home directory, outside any repo. | Documents, configuration, other projects and dotfiles are wiped. |
| 7 | core-catastrophic | `system-recursive-delete` | Deny | Recursive deletes of system paths such as `/` or `/usr`. | The operating system stops working and needs reinstalling. |
| 8 | core-catastrophic | `secret-store-recursive-delete` | Deny | Recursive deletes of credential stores such as `~/.ssh` or `~/.aws`. | SSH keys and cloud credentials are lost, locking the developer out of servers and accounts. |
| 9 | core-catastrophic | `disk-format` | Deny | Formatting or wiping a disk. | Everything on the disk is lost. |
| 10 | core-catastrophic | `disk-erase-macos` | Deny | Erasing a disk on macOS. | Everything on the volume is lost. |
| 11 | core-catastrophic | `dd-to-device` | Deny | Writing directly to a device with `dd`. | The partition table or filesystem is overwritten and the disk is corrupted. |
| 12 | core-catastrophic | `git-force-push-protected` | Deny | Force pushes whose refspec targets main, master or a release branch. | Teammates' commits on shared branches are erased and release history is rewritten. |
| 13 | core-catastrophic | `git-force-push` | Ask | Any other force push, including one with no explicit branch. | Remote commits on feature branches, including other people's, are overwritten. |
| 14 | core-catastrophic | `git-reset-hard` | Ask | `git reset --hard`. | Uncommitted work is discarded with no way to undo it. |
| 15 | core-catastrophic | `git-clean-force` | Ask | `git clean` with force. | Untracked files, such as new code or local configuration, are deleted for good. |
| 16 | core-catastrophic | `infra-destroy` | Ask | Infrastructure destroy commands such as `terraform destroy`. | Cloud infrastructure is torn down, causing outages and possible data loss. |
| 17 | core-catastrophic | `infra-apply-destroy` | Ask | `apply -destroy`. | The same as `infra-destroy`, through a different command. |
| 18 | core-catastrophic | `kubectl-delete-namespace` | Ask | Deleting a Kubernetes namespace. | Every workload, secret and volume claim in the namespace is removed. |
| 19 | core-catastrophic | `aws-destructive` | Ask | AWS CLI commands that delete resources. | Buckets, instances or databases are deleted, causing outages and data loss. |
| 20 | core-catastrophic | `gcloud-destructive` | Ask | Google Cloud CLI commands that delete resources. | The same as `aws-destructive`, on Google Cloud. |
| 21 | core-catastrophic | `az-destructive` | Ask | Azure CLI commands that delete resources. | The same as `aws-destructive`, on Azure. |
| 22 | exfiltration | `upload-secret-file` | Deny | A credential file sent to another host in the same command, such as `curl -F file=@~/.ssh/id_rsa`. | Private keys or cloud credentials are stolen, giving access to accounts and servers. |
| 23 | exfiltration | `upload-to-paste-site` | Deny | Uploads to paste and file-drop sites. | Code or secrets are published to public or anonymous sites. |
| 24 | exfiltration | `contact-capture-service` | Ask | Requests to request-capture and tunnel services, even GET requests that carry data in the URL. | Data leaks through a URL query string, a common exfiltration channel for injected prompts. |
| 25 | exfiltration | `upload-after-untrusted-input` | Ask | Data leaving the machine after the agent read untrusted content. | An injected page gets the agent to send code or secrets to an attacker. |
| 26 | exfiltration | `curl-upload` | Ask | Sending data with an HTTP request. | Files or data are posted to any endpoint without the developer noticing. |
| 27 | exfiltration | `remote-copy` | Ask | Copying files to another host, such as `scp` or `rsync`. | Whole repositories or folders are copied off the machine. |
| 28 | exfiltration | `raw-socket` | Ask | Opening a raw network connection, such as `nc` or `/dev/tcp`. | Reverse shells or data streams leave the machine, past HTTP-level checks. |
| 29 | exfiltration | `cloud-storage-upload` | Ask | Uploading files to cloud storage. | Data is copied to buckets an attacker controls, or made public. |
| 30 | exfiltration | `secret-to-network` | Deny | A credential in a request leaving the machine: a token in a URL, header or body. | Tokens reach untrusted hosts and the account is taken over. |
| 31 | exfiltration | `secret-in-network-command` | Deny | A network tool run with a credential in its arguments. | A token goes to an unexpected host and is also left in logs. |
| 32 | mcp-allowlist | `blocked-server` | Deny | An MCP server the organization has blocked. | A known-bad or banned tool gets access to code and data. |
| 33 | mcp-allowlist | `unapproved-server` | Ask | An MCP server in the catalog but not approved, such as one with a pending request. | Tools nobody has vetted run before security review. |
| 34 | mcp-allowlist | `unknown-server` | Ask | An MCP server not in the catalog at all (shadow MCP). Applies only when the organization has a catalog. | Unknown third-party tools get context and data with no oversight. |
| 35 | secrets | `secret-in-command` | Ask | A credential written out in a command. | The secret persists in shell history, logs and the agent's transcript. |
| 36 | secrets | `secret-written-to-file` | Ask | A credential hardcoded into a file. Writing it to a local `.env` file is expected and not asked about. | The secret is committed to git and leaks with the repository. |
| 37 | secrets | `secret-in-mcp-arguments` | Ask | A credential passed to an MCP tool. | A third-party tool stores or forwards the secret. |
| 38 | secrets | `dump-environment` | Ask | Printing the environment, such as `env` or `printenv`. | Every token in the environment ends up in the transcript. |
| 39 | secrets | `read-env-file` | Ask | Reading `.env` files and variants such as `.env.local`, but not `.env.example`. | Application secrets such as database passwords and API keys are exposed. |
| 40 | secrets | `read-ssh-key` | Ask | Reading an SSH private key. | The key is exposed and can be reused against servers and git hosts. |
| 41 | secrets | `read-cloud-credentials` | Ask | Reading cloud or cluster credentials. | Cloud administrator credentials are exposed. |
| 42 | secrets | `read-credential-store` | Ask | Any other credential store in home: keychains, `.netrc`, `.npmrc`, `.git-credentials`, the GitHub CLI token. | Registry and git tokens are exposed, which enables supply-chain pushes. |
| 43 | secrets | `read-private-key-file` | Ask | Reading a private key or certificate file. | TLS or signing keys are exposed, which enables impersonation. |
| 44 | secrets | `read-terraform-state` | Ask | Reading Terraform state, which holds secrets in plain text. | Every infrastructure secret in the state file is exposed. |
| 45 | secrets | `read-credentials-file` | Ask | Credential files by name anywhere, such as `credentials.json`, service-account keys and `secrets.yaml`. | Service-account or application credentials are exposed. |

## Tuning a rule

Repository and user policies can change how a built-in rule behaves, by its qualified ID. They can't weaken a rule an organization bundle has locked. See [Policy Integration](Policy-Integration.md) for the full syntax.

```yaml
schema: privometry.policy/v1
name: my-overrides
overrides:
  privometry/exfiltration:curl-upload:
    mode: monitor            # log matches instead of asking
  privometry/core-catastrophic:git-force-push: deny
exceptions:
  - rule: privometry/secrets:read-env-file
    target_path: "*/.env.test"
    reason: Test fixtures only, no real secrets
    expires_at: 2027-06-30T00:00:00Z
```

- **`mode: monitor`** keeps a rule matching and records it on the timeline, without blocking or asking.
- **Exceptions** are for narrow cases. Give them a reason and an expiry date.

The `rulepacks/community/example-helm-guard` pack in the repository is an example only. It isn't embedded and doesn't apply.
