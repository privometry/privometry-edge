#!/usr/bin/env bash
# Publishes docs/wiki/ to the GitHub wiki (or any other), which is a separate git
# repository (<project>.wiki.git). Pages in the repo link to each other as
# Page.md so the links work when browsing the source; the published copy
# links by page name (Page), the form both wikis resolve.
#
#   scripts/publish-wiki.sh https://github.com/<owner>/<repo>.wiki.git          # preview
#   scripts/publish-wiki.sh https://github.com/<owner>/<repo>.wiki.git --push   # publish
#
# The wiki repository exists only after the wiki is enabled and its first
# page is created in the web UI. docs/wiki/ stays authoritative: pages
# edited in the web UI are overwritten, and pages missing here are deleted.
set -euo pipefail

url="${1:?usage: scripts/publish-wiki.sh <wiki git URL> [--push]}"
push="${2:-}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if ! git clone --quiet --depth 1 "$url" "$work/wiki" 2>"$work/clone.err"; then
  echo "publish-wiki: cannot clone the wiki repository." >&2
  echo "Enable the wiki in the project settings and create its first page in the web UI; the wiki repository does not exist before that." >&2
  sed 's#://[^/@]*@#://***@#' "$work/clone.err" >&2
  exit 1
fi

rsync -a --delete --exclude .git "$root/docs/wiki/" "$work/wiki/"
find "$work/wiki" -name '*.md' -exec perl -pi -e 's/\]\(([A-Za-z0-9_-]+)\.md(#[^)\s]*)?\)/]($1$2)/g' {} +

cd "$work/wiki"
git add -A
if git diff --cached --quiet; then
  echo "The wiki is up to date."
  exit 0
fi
git diff --cached --stat
if [[ "$push" != "--push" ]]; then
  echo "Preview only; run again with --push to publish."
  exit 0
fi
git commit --quiet -m "Sync wiki from docs/wiki${SOURCE_REF:+ at $SOURCE_REF}"
git push --quiet origin HEAD
echo "Published $(git ls-files '*.md' | wc -l | tr -d ' ') pages."
