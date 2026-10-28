#!/usr/bin/env bash
# Runs Privometry for the GitHub Action (action.yml): builds the CLI from this
# action's source unless one is given, lists the files a pull request or push
# changes, validates the repo policy, scans the repository, and reports
# through annotations, a SARIF file and the job summary.
#
# It exits 0 when the gate fails and sets result=fail, so action.yml can
# upload the SARIF report before failing the job. Errors exit non-zero.
set -euo pipefail

fail_on="${INPUT_FAIL_ON:-high}"
sarif="${INPUT_SARIF_FILE:-privometry.sarif}"
tmp="${RUNNER_TEMP:-$(mktemp -d)}/privometry"
mkdir -p "$tmp"
out="${GITHUB_OUTPUT:-/dev/null}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

case "$fail_on" in
  low | medium | high | critical | none) ;;
  *) echo "::error title=Privometry::fail-on must be low, medium, high, critical or none, not '$fail_on'"; exit 2 ;;
esac

bin="${INPUT_PRIVOMETRY:-}"
if [[ -z "$bin" ]]; then
  src="$(cd "$GITHUB_ACTION_PATH/.." && pwd)"
  bin="$tmp/bin/privometry"
  (cd "$src" && CGO_ENABLED=0 go build -trimpath -o "$bin" ./cmd/privometry)
fi
"$bin" version

cd "${INPUT_WORKING_DIRECTORY:-.}"
cd "$(git rev-parse --show-toplevel)"
case "$sarif" in /*) ;; *) sarif="$PWD/$sarif" ;; esac

# The commit to compare against: the pull request's base, or the commit
# before a push. A new branch's push has no previous commit.
base="${INPUT_BASE:-}"
if [[ -z "$base" && -f "${GITHUB_EVENT_PATH:-}" ]]; then
  case "${GITHUB_EVENT_NAME:-}" in
    pull_request | pull_request_target) base="$(jq -r '.pull_request.base.sha // empty' "$GITHUB_EVENT_PATH")" ;;
    push) base="$(jq -r '.before // empty' "$GITHUB_EVENT_PATH")" ;;
  esac
fi
[[ "$base" =~ ^0+$ ]] && base=""

changed=()
changed_count=""
if [[ -n "$base" ]]; then
  if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
    git fetch --no-tags --depth=1 origin "$base"
  fi
  # Against the pull request's merge commit, this is exactly what the
  # pull request changes.
  git diff --name-status --no-renames "$base" HEAD >"$tmp/changes.txt"
  changed=(--changed "$tmp/changes.txt")
  changed_count="$(grep -c . "$tmp/changes.txt" || true)"
  echo "Comparing with $base: $changed_count changed file(s)."
fi

result=pass
policy_note=""
if [[ "${INPUT_VALIDATE_POLICY:-true}" == "true" && -f .privometry/policy.yaml ]]; then
  if "$bin" policy test .privometry/policy.yaml >"$tmp/policy.txt" 2>&1; then
    policy_note="Repo policy \`.privometry/policy.yaml\` passes its tests."
  else
    result=fail
    policy_note="Repo policy \`.privometry/policy.yaml\` fails its tests."
    echo "::error file=.privometry/policy.yaml,title=Privometry policy::The repo policy fails privometry policy test. See the job log."
  fi
  cat "$tmp/policy.txt"
fi

gate=()
[[ "$fail_on" != none ]] && gate=(--fail-on "$fail_on")
set +e
"$bin" scan --no-machine --repo . --format sarif --output "$sarif" ${gate[@]+"${gate[@]}"} ${changed[@]+"${changed[@]}"}
code=$?
set -e
case "$code" in
  0) ;;
  1) result=fail ;;
  *) echo "::error title=Privometry::privometry scan failed (exit $code)"; exit "$code" ;;
esac
"$bin" scan --no-machine --repo . --format json --output "$tmp/scan.json" ${changed[@]+"${changed[@]}"}
"$bin" scan --no-machine --repo . --format table ${changed[@]+"${changed[@]}"}

findings="$(jq '(.findings | length) + (.content_findings | length)' "$tmp/scan.json")"

if [[ "${INPUT_ANNOTATIONS:-true}" == "true" ]]; then
  # Workflow commands: one annotation per finding in a repository file.
  jq -r '
    def esc: gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A");
    def prop: esc | gsub(":"; "%3A") | gsub(","; "%2C");
    def level: if .severity == "critical" or .severity == "high" then "error"
      elif .severity == "medium" then "warning" else "notice" end;
    def at: "file=\(.path | prop)" + (if (.line // 0) > 0 then ",line=\(.line)" else "" end);
    (.findings[] | select(.tier == "project" and (.path // "") != "")
      | "::\(level) \(at),title=\("Privometry: " + .check | prop)::\(.message + " " + .fix | esc)"),
    (.content_findings[] | select(.tier == "project")
      | "::\(level) \(at),title=\("Privometry: " + .title | prop)::\(.excerpt + " (" + .detector + ")" | esc)")
  ' "$tmp/scan.json"
fi

{
  echo "## Privometry"
  echo
  if [[ -n "$changed_count" ]]; then
    echo "Compared with \`${base:0:12}\`: $changed_count changed file(s). Gate: fail on \`$fail_on\`."
  else
    echo "Whole-repository scan (no base commit to compare with). Gate: fail on \`$fail_on\`."
  fi
  [[ -n "$policy_note" ]] && { echo; echo "$policy_note"; }
  echo
  if [[ "$findings" == 0 ]]; then
    echo "No findings."
  else
    echo "| Severity | Where | Finding |"
    echo "| --- | --- | --- |"
    jq -r '
      def cell: tostring | gsub("\\|"; "\\|") | gsub("\n"; " ");
      def where: (.path // "") + (if (.line // 0) > 0 then ":\(.line)" else "" end);
      def rank: {"critical": 0, "high": 1, "medium": 2, "low": 3}[.severity] // 4;
      [(.findings[] | {severity, w: where, text: (.message + " " + .fix)}),
       (.content_findings[] | {severity, w: where, text: (.title + ": " + .excerpt + " (" + .detector + ")")})]
      | sort_by(rank) | .[]
      | "| \(.severity | ascii_upcase) | `\(.w | cell)` | \(.text | cell) |"
    ' "$tmp/scan.json"
  fi
  allowlisted="$(jq '.allowlisted // 0' "$tmp/scan.json")"
  if [[ "$allowlisted" != 0 ]]; then
    echo
    echo "$allowlisted finding(s) skipped by allowlists in \`.privometry/policy.yaml\`."
  fi
} >>"$summary"

{
  echo "result=$result"
  echo "sarif-file=$sarif"
  echo "findings=$findings"
  echo "changed-files=$changed_count"
} >>"$out"
echo "Privometry: $findings finding(s); result: $result."
