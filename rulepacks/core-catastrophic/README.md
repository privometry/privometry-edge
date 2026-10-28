# privometry/core-catastrophic

Blocks or asks before actions that destroy data, history or infrastructure in one step. Ships inside the Privometry sensor and is on by default.

| Rule | Verdict | What it catches |
|---|---|---|
| `home-recursive-delete` | deny | Recursive delete in your home directory, outside a repo |
| `system-recursive-delete` | deny | Recursive delete of a system path |
| `secret-store-recursive-delete` | deny | Recursive delete of `~/.ssh`, `~/.aws` and similar |
| `git-force-push-protected` | deny | Force push to main, master or a release branch |
| `git-force-push` | ask | Any other force push |
| `git-reset-hard` | ask | `git reset --hard` |
| `git-clean-force` | ask | `git clean -f` |
| `db-drop` | deny | Dropping a database, schema or table, from any tool |
| `infra-destroy` | ask | `terraform`, `tofu`, `terragrunt`, `pulumi`, `cdk` destroy |
| `infra-apply-destroy` | ask | `terraform apply -destroy` |
| `kubectl-delete-namespace` | ask | Deleting a Kubernetes namespace |
| `aws-destructive`, `gcloud-destructive`, `az-destructive` | ask | Deleting buckets, databases, clusters, projects or resource groups |
| `disk-format`, `disk-erase-macos`, `dd-to-device` | deny | Formatting, erasing or overwriting a disk |

Fail mode: `closed`. If the Privometry daemon is down, the hook client still blocks these actions.

## Tuning

Tighten a rule in your policy, for example deny every force push:

```yaml
overrides:
  privometry/core-catastrophic:git-force-push: deny
```

Loosen one only for a limited time, with an exception:

```yaml
exceptions:
  - rule: privometry/core-catastrophic:infra-destroy
    repo: github.com/acme/sandbox-infra
    reason: Throwaway sandbox stacks
    expires_at: 2026-12-31T00:00:00Z
```

## Tests

`tests/` holds a matching and a non-matching case for every rule. Run them with `go test ./rulepacks/`.
