# Policy engine

How an agent action becomes a verdict. Entry point: `policy.Decide` in `internal/policy`.

```
action ──► intent.Extract ──► one request per command and target ──► engine (Cedar) ──► strongest verdict
                                                                        ▲
             packs + user + repo + org policy ──► merge ──► compiler ───┘
```

## Extraction (`internal/policy/intent`)

**Shell parsing.** Commands are parsed with `mvdan.cc/sh`, so pipelines, `&&` chains, subshells and `$(...)` are all seen. Wrappers are peeled (`sudo`, `doas`, `env`, `timeout`, `nice`, `xargs`, `nohup`, `time`, `stdbuf`, …), and the parser descends into `sh -c`, `bash -c`, `eval`, `find -exec`, and package runners (`npx prisma migrate reset` yields both `npx` and `prisma`), and on Windows into `cmd /c` and `powershell`/`pwsh` `-Command` or `-EncodedCommand`. Nesting stops at depth 4. A line that does not parse is treated as high risk.

**Windows command lines** go through the same parser. Before parsing, backslashes in Windows paths (those starting `C:\`, `.\`, `..\`, `~\`, `%VAR%\`, `$env:VAR\` or `$HOME\`, or a lone `\` ending the line, the current drive's root) become forward slashes, so the shell grammar does not read them as escapes. `rmdir`, `rd`, `del` and `erase` take cmd.exe switches (`/s`, `/Q`) as flags. PowerShell's `Remove-Item` and its aliases (`ri`, `rm`, `rmdir`, `rd`, `del`, `erase`) take parameters in any case and abbreviated, `-Path:value`, and comma-separated path lists.

**Working directory:** `cd` and `pushd` change where later commands in the same line resolve relative paths, so `cd ~ && rm -rf old` targets the home folder. Subshells and conditional branches are not scoped separately.

**Facts per command:** `program` (base name), `subcommand` (up to four positional words), `flags` (as written, values dropped, letter groups also split), `target_path` and `path_class` per path, `host` per URL or `user@host:` argument.

**Path classes:** `secret_store` (`~/.ssh`, `~/.aws`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, keychains, …), `repo`, `temp`, `home`, `system`, `other`. Secret files are also recognized by name anywhere: `.env*` (not `.example`/`.sample`/…), private keys, `*.pem`, `credentials.json`, service-account files, `*.tfstate`.

**Intents**

| Intent | Detected from |
|---|---|
| `recursive_delete` | `rm -r`, `find -delete`, cmd.exe `rmdir`/`rd`/`del`/`erase` with `/s`, PowerShell `Remove-Item` (or an alias) with `-Recurse`; per target, so the path class decides severity |
| `force_push` | `git push` with `--force`, `-f`, `--force-with-lease`, `--mirror` or a `+` refspec |
| `db_drop` | `DROP DATABASE/SCHEMA/TABLE`, `TRUNCATE`, `FLUSHALL`, `dropDatabase()` in any argument; `dropdb`, `mysqladmin drop`, `prisma migrate reset`, `rails db:drop`, `manage.py flush`, `supabase db reset` |
| `secret_read` | Reading a secret file; `env`, `printenv` |
| `package_install` | Install subcommands of npm, pnpm, yarn, bun, pip, uv, poetry, cargo, go, brew, apt, gem, …; `npx`, `uvx`, `bunx`, `dlx` |
| `network_upload` | `curl -T/-d/-F/--json`, `wget --post-*`, `scp`/`rsync` to a host, `nc`, cloud copies to `s3://`/`gs://`, `gh gist create` |

**Risk** drives `unmatched: auto`, which allows `none` and `low` and asks for anything higher:

| Risk | Examples |
|---|---|
| none | Read-only commands (`ls`, `cat`, `grep`, `git status/log/diff`), reading repo files |
| low | Builds and tests, routine git, writes and recursive deletes inside the repo or a temp folder, plain downloads, read-only MCP tools (by name: `get_*`, `list_*`, `search_*`, …) |
| medium | Unknown programs, package installs, writes in the home folder, inline code (`python -c`), `git reset --hard`, other MCP tools |
| high | Uploads, secret reads, `sudo`, writes to system or credential folders, writes to agent/git/shell config (hooks, `.mcp.json`, `.zshrc` — a persistence technique), `curl … | sh`, infrastructure changes, paths built from variables |
| critical | Recursive deletes of home, system or credential folders; database drops; force pushes; formatting or overwriting disks |

## Merging (`internal/policy/merge`)

Layers, from least to most authority: built-in packs, user policy, repo policy, organization policy. All rules are evaluated together and the strongest verdict wins.

- Privometry's packs are always on. `extends` adds other packs or pins a version range.
- Any layer may tighten any rule. Loosening (weaker verdict, monitor mode, weaker fail mode, or an exception) is allowed only for built-in rules, organization rules marked `overridable`, or by the organization itself. Locked organization rules cannot be changed by lower layers.
- Repo and user overrides of one rule combine by the strongest setting, so a developer cannot undo a repo's tightening; an organization override replaces them.
- Exceptions compile into an `unless` clause on their rule; one without conditions disables the rule; an expired one is dropped (`merge.NextExpiry` says when to merge again). Organization exceptions need `approved_by`.
- `unmatched` takes the strictest value across layers. Repo and user policies can only tighten fail modes; defaults are catastrophic closed, secrets and exfiltration ask, the rest open.
- A disallowed or broken setting is ignored with a diagnostic, never a failure: a bad repo file must not switch protection off.

## Rule packs

Four packs ship in the sensor (`rulepacks/`), each with tests that run in CI:

| Pack | Rules | What it does |
|---|---|---|
| `privometry/core-catastrophic` | 17 | Blocks or asks before destroying data, history, infrastructure or disks |
| `privometry/secrets` | 8 | Asks before reading `.env` files, SSH keys, cloud credentials, private keys, Terraform state, or printing the environment |
| `privometry/exfiltration` | 8 | Blocks sending credential files and uploads to paste sites; asks before capture services, other uploads, and any upload after untrusted input |
| `privometry/mcp-allowlist` | 3 | Enforces an organization's MCP catalog; inactive until a catalog exists |

## Testing policies: `privometry policy test`

```bash
privometry policy test                                      # the repo's .privometry/policy.yaml and ~/.privometry/policy.yaml
privometry policy test .privometry/policy.yaml                   # one policy, with tests from .privometry/tests/
privometry policy test rulepacks/secrets                    # a rule pack, with the release-gate checks
privometry policy test --command "cd ~ && rm -rf old"       # explain one action under the current policies
privometry policy test --read .env --untrusted
```

A policy file is merged with the shipped packs and run against `tests/*.test.yaml` next to it. In policy tests, `expect.rule` names one of the policy's own rules that must be among the deciding rules, and `expect.rules` gives the exact set of deciding rules as qualified IDs (`[]` means none, so the unmatched default decided). Pack tests are stricter: the pack is evaluated alone, `expect.rule` must be the only deciding rule, and every rule needs a matching and a non-matching test. `policies/examples/web-app/` is a worked example.

Explain mode prints the verdict, deciding rules and message, then every extracted request with its facts, risk, reason and own verdict, and any merge diagnostics. Exit codes: 0 pass, 1 a test failed, 2 usage error.

## Decision

Each request is evaluated with the three-step mapping from Contracts v1; the strongest verdict across requests wins. `Source` is `policy` when a rule decided or the unmatched default asked, and `auto_approve` when nothing matched and the risk allowed it. The decision carries the deciding rules, a one-line message, the risk reason, and any monitor-mode `would_verdict`.

Measured on an M-series Mac: p50 11 µs, p95 55 µs per decision; a three-command line takes about 29 µs.

## Known gaps

- The engine itself keeps no session state: the daemon tracks untrusted input and injected content per session and passes `UntrustedInputSeen` and `InjectionSeen` (see `docs/daemon.md`).
- `catalog_status` is never set: it needs the bundle catalog and risk feed (P2).
- Organization policies are merged from their YAML source; using a signed bundle's precompiled Cedar arrives with bundle sync (P2).
- Inline interpreter code (`python -c`, `node -e`) is not analysed beyond its risk level.
- Windows paths are classified in forward-slash form and compared without regard to case (`C:\Users\dev\.ssh` is a secret store, `C:\Windows` and `Program Files` are system); `%USERPROFILE%` and `$env:USERPROFILE` count as the home folder, other `%VAR%` paths are not resolved, and a bare drive root such as `D:\` is system. PowerShell is read with the POSIX shell grammar, which covers simple commands, `;`, `|` and quoting; not covered are pipeline input (`Get-ChildItem C:\x -Recurse | Remove-Item` has no path on `Remove-Item`), the `&` call operator at the start of a line (does not parse, so high risk), .NET calls such as `[IO.Directory]::Delete()`, script blocks, UNC paths (`\\server\share`), and relative paths without a leading `.\` (`build\out` reads as `buildout`, still in the same folder).
