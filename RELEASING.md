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
  to draft the kit changes for that issue. The session reads the issue with
  `gh issue view <number> --json author,body`: the watcher's own text, without
  comments, which anyone can add on a public repository.
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
  --generate-hashes` (install uv first, for example `pip install uv` in a
  scratch environment). Rebuild `checks/pytest-requirements.txt` the same
  way when the fixture app's pytest changes.
- Semgrep and ZAP: change the tag and the digest together. The self-test
  fails when the version the image reports doesn't match its tag.

Each change is a pull request. Merge it once its checks pass.

When Claude drafts the changes for a kit-update issue, review the draft
like any other pull request before merging:
- the self-test passes, so every planted defect is still caught;
- a code review and a security review ran on the diff, and their findings
  are fixed or answered in the pull request;
- every new version, checksum or image digest matches what its source link
  shows, checked by you, not copied from the issue;
- the draft changes only what the issue's ticked items asked for.

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

## Checking the kit upgrade

When the owner says "check the kit upgrade", or before tagging a release
that changes what projects must call, check that a real project picks up a
kit release through Dependabot. Use a throwaway project that calls the kit
(a practice project, never a client's production branch).

1. **Find the upgrade pull request.** In the test project, list
   Dependabot's open pull requests and find the one that changes the kit's
   `uses: atwine/security-kit/...@<sha>` lines. Dependabot waits a set
   number of days after a release before offering it (the cooldown: 7 days
   in the kit's template), and opens the pull request into the branch its
   `target-branch` names (for example `development`). None yet means the
   cooldown hasn't passed: wait.
2. **Check it points at the release.** The new commit must be the tag's
   commit, and the version comment next to it must name that tag:

   ```bash
   git ls-remote --tags https://github.com/atwine/security-kit
   ```

   For the kit's tags (annotated), the line ending in `^{}` gives the
   commit; a tag without that line points at its commit directly.
3. **Check its run.** Both checks that decide pass or fail must run on the
   pull request. Read the result with the `security-report` skill (or the
   run's summary page): the score, the checklist line and the results
   table should all be there for a release that has them. A new failure is
   fine when it is a real finding the new release now catches; say which.
4. **Check what the project must change.** Read the release's
   `CHANGELOG.md` entry. If the release adds something the project's own
   workflow must call (as the release after v0.1.0 adds the `score` job), make that change in
   the same pull request, or note it for the owner.
5. **Decide.** If the upgrade works, merge the pull request (in a throwaway
   project) or leave it for the owner, and go on with the release steps
   above. If it doesn't, don't tag: fix the kit first, in a pull request,
   and check again.
