# Publishing the Wiki

The canonical wiki source lives in `docs/wiki/` so documentation changes can be reviewed with code. `Home.md` is the landing page and `_Sidebar.md` defines navigation, as GitHub wikis expect.

A wiki is a separate Git repository (`<project>.wiki.git`), so files in `docs/wiki/` do not appear in the Wiki tab until they are published. `scripts/publish-wiki.sh` copies them there. Pages link to each other as `Page.md` so links work when browsing the source; the script rewrites them to `Page`, the form wikis resolve.

## One-time setup

The wiki repository does not exist until the wiki has one page:

1. Settings → General → Features → enable **Wikis**.
2. Open the Wiki tab and create the first page (any content, for example a page named `Home`). Publishing replaces it.

## Publish from your machine

```sh
scripts/publish-wiki.sh https://github.com/<owner>/<repo>.wiki.git           # preview the changes
scripts/publish-wiki.sh https://github.com/<owner>/<repo>.wiki.git --push    # publish
```

The script uses your normal Git credentials, shows what changes, and pushes only with `--push`. `docs/wiki/` stays authoritative: pages edited in the web UI are overwritten, and pages missing from `docs/wiki/` are deleted.

## Publish automatically on GitHub

`.github/workflows/wiki.yml` runs the script after `docs/wiki/` changes on `main`, and on demand from the Actions tab (**wiki → Run workflow**). It pushes with the workflow's `GITHUB_TOKEN` and needs only `contents: write`; complete the one-time setup first.

## Editing rules

- Link between wiki pages as `Page-Name.md`; the publish step rewrites the links.
- Keep page filenames stable after publication because external links may depend on them.
- Put code behavior and flags in the same pull request as their documentation changes.
- Avoid customer names, internal URLs, tokens, screenshots containing data, or unpublished security details.
- Verify links and command examples before publishing.
