# Privometry GitHub Action

Checks every pull request for changes that affect AI coding agents (PRD EDGE-30, SCAN-08):

- **Changed agent files.** Edits, additions and deletions of files agents act on in this repo: Claude Code, Cursor and Codex settings, hooks, permissions, MCP server declarations, skills, rules and instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules/*.mdc`, also nested in subfolders), and the repo's Privometry policy. Hooks, permissions, MCP servers and the policy are medium severity; instructions, rules and skills are low.
- **Content detectors.** The same detector packs the sensor runs: credentials, injected and safety-weakening instructions, and hidden content. They run on the agents' files and on every changed text file.
- **Posture.** Repo hooks, repo MCP servers and unpinned servers, as in `privometry scan`.
- **Policy.** `.privometry/policy.yaml`, when present, must pass `privometry policy test`.

Findings appear as pull request annotations, in the job summary and in a SARIF report. The job fails when a finding meets `fail-on` (default `high`) or the policy fails its tests.

## Usage

Use it as `privometry/privometry-edge/action@<tag>`. On GitLab, run the commands at the end of this page in a merge request pipeline job.

```yaml
name: privometry
on: pull_request
permissions:
  contents: read
jobs:
  privometry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: <owner>/privometry-edge/action@<ref>
        with:
          fail-on: high
```

To see findings in code scanning, add `security-events: write` to `permissions` and `upload-sarif: "true"` to `with`.

The action builds `privometry` from its own source with the Go version in its `go.mod`, using `actions/setup-go` (this sets Go for later steps of the job too). Pass `privometry: path/to/privometry` to use a binary you installed.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `fail-on` | `high` | Fail at this severity or above: `low`, `medium`, `high`, `critical`, or `none` to never fail on findings |
| `validate-policy` | `true` | Test `.privometry/policy.yaml` when the repo has one |
| `annotations` | `true` | Annotate findings on the pull request |
| `upload-sarif` | `false` | Upload the SARIF report to code scanning |
| `sarif-file` | `privometry.sarif` | Where to write the SARIF report |
| `base` | the pull request's base, or the commit before a push | Commit to compare against; without one, changed-file checks are skipped and only the whole-repo scan runs |
| `working-directory` | `.` | A folder in the repository; the scan always covers the whole repository |
| `privometry` | build from source | Path to a `privometry` binary |

Outputs: `result` (`pass` or `fail`), `sarif-file`, `findings` and `changed-files`.

## Accepted findings

Fake keys in test fixtures and documented example values are expected. Allowlist them in the repo policy instead of lowering the gate:

```yaml
# .privometry/policy.yaml
schema: privometry.policy/v1
name: my-service
allowlist:
  - detectors: [privometry/credentials:*]
    paths: [test/fixtures/*]
    reason: Fake keys used by the tests
  - detectors: [privometry/credentials:aws-access-key]
    values: [AKIAIOSFODNN7EXAMPLE]
    reason: AWS's documented example key
```

A change to the policy file is itself flagged, so reviewers see when someone adds an entry. The same allowlist applies to `privometry scan` and to the sensor on developers' machines.

## How it compares

On `pull_request` events the action fetches the base commit and lists changes with `git diff --name-status <base> HEAD`. Against the merge commit `actions/checkout` creates, that is exactly what the pull request changes. The list goes to `privometry scan --changed`. The same check runs locally or in any CI system:

```bash
git diff --name-status --no-renames origin/main...HEAD | privometry scan --no-machine --repo . --changed - --fail-on high
```
