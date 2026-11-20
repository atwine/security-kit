# Releasing a kit version

`main` accepts changes only through pull requests, and only when the
self-test ("Each planted defect is caught, and the clean app passes") and
the kit's own security checks pass. Nobody can push to `main` directly,
including the owner. Release tags (`v*`) can't be moved or deleted once
pushed.

## Where changes come from

- **The monthly watcher** (`watch/`) opens a `kit-update` issue when a
  scanner, an OWASP list, a critical advisory or CISA's list of actively
  exploited holes has something new. To act on it, ask Claude in a session
  to draft the kit changes for that issue.
- **Dependabot** proposes updates to the kit's own GitHub Actions and the
  fixture app's libraries.
- **Your own fixes and additions.**

When a kit-update issue names a new scanner version, update its pin where
the kit records it:
- gitleaks: `GITLEAKS_VERSION` and `GITLEAKS_SHA256` in `scans.yml`. Take the
  checksum from the release's checksums file, and check it against your own
  hash of the download.
- pip-audit: rebuild `checks/pip-audit-requirements.txt` with
  `uv pip compile` on a file holding `pip-audit==<version>`, using
  `--python-version 3.12 --python-platform x86_64-manylinux_2_28
  --generate-hashes`.
- Semgrep and ZAP: change the tag and the digest together. The self-test
  fails when the version the image reports doesn't match its tag.

Each change is a pull request. Merge it once its checks pass.

## Releasing

1. Merge the pull requests that belong in the release.
2. Look on OWASP's GenAI site (genai.owasp.org) for a newer edition of
   the Top 10 for Agentic Applications. The watcher can't follow that
   list, because its GitHub copy holds only working drafts. If there is a
   newer edition, update the checklist items that cite it (`ASI` in the
   Sources column) before releasing.
3. In one more pull request, add the version's entry to `CHANGELOG.md`:
   what changed for projects, and anything a project must do. If the
   checklist changed, put the release's version in its version line.
4. After it merges, tag that merge commit on `main` and push the tag:

   ```bash
   git switch main && git pull
   git tag -a v0.2.0 -m "security-kit v0.2.0"
   git push origin v0.2.0
   ```

   Pick the number by what projects feel:
   - **major**: projects must change something themselves (a renamed
     input, a check that now fails where it passed before);
   - **minor**: new checks, templates or checklist items that don't break
     a passing project;
   - **patch**: fixes and scanner updates.

5. Projects pinned to an earlier release get a Dependabot pull request
   after their cooldown (7 days in the kit's template). It pins the new
   release's full commit SHA.

Check the commit before you tag it: a pushed tag can't be moved. If a
release turns out wrong, fix it in the next one.
