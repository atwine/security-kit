# Changelog

## Unreleased

- Monthly watcher (`watch/`, `watch.yml`): checks the scanners the kit
  pins, the OWASP lists behind the checklist, critical advisories for
  FastAPI, Starlette, Next.js and React, and CISA's list of actively
  exploited holes, then opens one `kit-update` issue with a source link
  for each item. No AI, no secret.
- The self-test also runs the watcher's tests.
- `RELEASING.md`: how changes reach `main` and how a version is released.
- `main` now takes changes only through pull requests whose self-test and
  security checks pass; release tags can't be moved or deleted.
- Semgrep 1.186.0 (was 1.179.0) and ZAP 2.17.0 (was 2.16.1), from the
  watcher's first `kit-update` issue (#2).
- Checklist 0.2: SK-02 now says audits can't see a library copy that a
  framework bundles inside itself, so projects also follow the
  framework's own advisories (from #2).
- `RELEASING.md` checks the OWASP Top 10 for Agentic Applications by hand
  before each release, since the watcher can't follow it.
- The verdict is no longer decided where the project's code runs (review group A).
  Each workflow now has a second job that decides pass or fail on a fresh
  machine from GitHub's record of each check. It keeps the old check names,
  "Security checks (security-kit)" and "Website scan (security-kit, ZAP
  baseline)", so existing branch protection still points at the deciding
  job. The kit's files move out of the project's folder before any project
  code runs, so Semgrep no longer needs to exclude a `.security-kit` folder.
  Steps that run project code come last (they later moved to their own job,
  below). The website scan prepares its rules
  before the app is installed, checks them again before scanning, and calls
  bash and docker by full path.
- `fail-on-findings` and `self-test-defect` work only for the kit's own
  self-test; any other repository gets findings as failures, with a warning.
- The workflows refuse `pull_request_target` and `workflow_run`, which would
  scan the base branch instead of the change.
- The pin check skips virtual environments by their `pyvenv.cfg`, not by
  folder name, so a project folder called `env` or `venv` is checked.
- Self-test: three new planted defects, a forged verdict, risky code in a
  `.security-kit` folder, and a loose pin in an `env` folder. Each must be
  caught.
- The self-test proves each catch (review group C). A catch counts only when
  the check's own report names the planted item. Every other check must pass
  in each defect run, and a missing result fails. Before this, a pip crash on
  a version conflict counted as catching the vulnerable library. The rules
  moved into `selftest/verdict.py`, with tests.
- The planted vulnerable Python library is now urllib3 1.26.4, which installs
  cleanly, so pip-audit really looks it up. A planted lodash 4.17.15 lockfile
  gives npm audit its first test. Caught 10 of 10.
- Each check also writes its tool's report to the runner's temporary folder.
  npm audit and pip-audit write JSON now, so their steps print what they
  found through `checks/findings.py`: each vulnerable package with its
  advisories, links and fixed versions. `checks/pins.py` takes `--report`.
- `scans.yml` has new `evidence-read` and `evidence-run` outputs, and
  `site-scan.yml` an `evidence` output. They're filled only in the kit's own
  repository, for the self-test, and never decide a project's verdict.
- Follow-ups from group A's late code and security reviews:
  - The code checks run in two jobs. gitleaks, Semgrep, the pin check and
    npm audit run on a machine where no project code runs. pip-audit and
    the access tests run on their own.
  - The deciding step is now `checks/gate.py`, with tests. It expects a
    fixed list of results and fails on a missing or unknown one. Before,
    project code could register the word "failure" as a secret. GitHub then
    dropped every failed result, and the gate passed.
  - Every job fetches the kit before the project, so the kit's own fetch
    can't empty a project folder named `.security-kit`.
  - The website scan's steps after the app starts ignore SHELLOPTS,
    imported bash functions, and loader and docker settings that the app
    adds through `$GITHUB_ENV`, and call `sha256sum` by full path. Before,
    one `SHELLOPTS=noexec` line made the scan run nothing and pass.
  - The README and the project template name the real checks to require,
    such as "code / Security checks (security-kit)".
  - Self-test: two new planted defects, `mask-failure` and
    `site-env-bypass`, and a test that every job fetches the kit first.
- Checks no longer pass without checking (review group B):
  - `checks/inventory.py` finds every npm lockfile, requirements file,
    pyproject project and ACCESS.md the project tracks under the working
    folder (and an ACCESS.md at the repository root).
    Anything no check can read fails that check as "not checked".
  - npm audit runs on a clean copy of each lockfile against the public
    registry, so a project `.npmrc` can't redirect it.
  - pip-audit also checks pyproject.toml projects. A pyproject that lists
    libraries another way (poetry, pdm, filled in at build time) counts as
    not checked, and so do setup.py, setup.cfg, Pipfile and requirements.in
    with nothing pip-audit reads beside them. A lockfile (uv, poetry, pylock)
    counts as checked only with a requirements file exported next to it,
    because pip-audit doesn't read locked versions. Packages pip-audit can't
    look up count as not checked.
  - The access-rule check finds test files with "access" in their name for
    each ACCESS.md, runs each from the folder holding its requirements with
    the project's pytest settings overridden, and installs pytest when the
    project lacks it. `access-tests` now names one or more files and is
    empty by default. An ACCESS.md with no access tests, or a run where no
    test ran, fails.
  - gitleaks uses the kit's own settings (`checks/gitleaks.toml`), and
    Semgrep the kit's `.semgrepignore`, with no file size limit. Any file
    Semgrep reports it couldn't scan (a timeout, a parse failure) fails as
    not checked.
  - The summary lists the project's scanner settings files, which are now
    ignored, and its inline skip comments (`gitleaks:allow`, `nosem`), which
    still apply. A `gitleaks:allow` that exists only in older commits still
    hides a secret and isn't listed.
  - Self-test: eight new planted defects, one per gap.
- The website scan checks what ZAP can't see over plain HTTP (review group D):
  - A new `site_policy` check (`checks/site_policy.py`) fetches the start
    page, the same-site pages it redirects to, and up to 19 pages it links
    to, checking every response on the way. A page that can't be fetched
    fails as KIT-FETCH. It fails on a missing HSTS,
    Referrer-Policy or Permissions-Policy header, a cookie without Secure or
    SameSite, and CORS that lets any site read a response. A
    `KIT-...<tab>IGNORE<tab>(reason)` line in the rules file accepts one;
    the reason is required. HttpOnly stays with ZAP's own rule 10010, which
    works over plain HTTP.
  - ZAP starts with `-silent`, so it no longer downloads rule updates during
    the scan and the pinned image's rules decide.
  - The checklist's SK-17, SK-20 and SK-22 say which check covers what.
  - Self-test: five new planted website defects (one is a start page that
    redirects to a page with an insecure cookie) and a second
    environment-line bypass aimed at the kit's check. `missing-headers` now
    drops only the three headers ZAP checks.
- The pin check misses fewer loose pins (review group E):
  - It reads requirements files the way pip does: comment and backslash
    handling, every option on a line, quoted values and a byte-order mark.
    It follows files pulled in with -r and -c (one pulled in from a URL
    fails), and needs a literal version after ==. A second package source
    counts across every file pip reads with it.
  - Editable and direct installs must name a full commit hash; archive
    URLs need their hash. A hash elsewhere in the URL no longer counts.
  - --find-links and abbreviated --extra-index count as second sources,
    and a --hash mentioned only in a comment doesn't count as hashing.
  - A requirements option the check doesn't know fails it, and so does
    --trusted-host (it turns off certificate checks). A replacement
    --index-url is allowed and printed as a note.
  - Workflow and composite-action images (container:, services:, image:,
    including flow style) need a digest; an action input named image
    doesn't count. Dockerfile base images, COPY --from and RUN --mount
    from= images need a digest too, with ARG defaults filled in;
    Dockerfiles used to warn. Every spelling of uses: is read.
  - A pyvenv.cfg committed to the repository no longer hides its folder.
  - Pre-commit hooks pinned by tag fail. The kit's own hook and the
    template's are frozen to gitleaks v8.30.1's commit (review item F4).
  - Self-test: three new planted pin defects.
- The kit's own tools are pinned by the kit (review group F):
  - gitleaks is checked against a checksum recorded in `scans.yml`, not
    one downloaded from the same release.
  - pip-audit installs from `checks/pip-audit-requirements.txt`, which pins
    it and every library it needs with hashes. When a project doesn't
    install pytest, the access-rule check installs it from
    `checks/pytest-requirements.txt` the same way. pip-audit still upgrades
    pip inside its own temporary environments, unpinned.
  - The self-test checks that the Semgrep and ZAP versions that ran match
    the tags pinned next to their digests, so a tag bumped without its
    digest is caught.
  - Semgrep's default rules stay live, because Semgrep's rules licence
    keeps the kit from pinning a copy. The self-test now also runs weekly,
    and the README no longer claims those rules are pinned.
- The monthly watcher (review group G):
  - Outside text loses HTML codes and www. links too, and a link can't be
    rebuilt by stripping characters.
  - Only issues the watcher's own bot wrote can mark an update as already
    reported.
  - Real runs have their own queue, so a pull-request preview can't cancel
    one, and the default window is 62 days.
  - Every source is tried even when one fails; the run reports what it
    found and then fails. A CISA entry in an odd shape fails the run.
  - Each issue is locked when opened and tells the drafting session to use
    only the watcher's text.
  - The weekly self-test fails when the watcher hasn't succeeded in 40 days.
- Docs and release prep (review group I):
  - The kit has its own `SECURITY.md`; reports go through GitHub's private
    reporting form.
  - Checklist claims now match the checks: SK-02 says npm audit fails on
    high and critical holes in shipped libraries, SK-11 says the access
    tests decide route coverage and that a project without `ACCESS.md`
    passes, and SK-52 says the release gate stops only Claude's own pull
    requests.
  - The Next.js guide warns not to switch off ZAP rule 10038 during the
    warn-only Content-Security-Policy step.
  - `RELEASING.md` says how to review a change Claude drafts from a
    kit-update issue.
  - gitleaks prints each leak's file and line (`-v`, secrets still
    redacted). Downloads use `curl --proto =https`, and file arguments
    follow `--`.
  - The watcher no longer tracks Vercel, and its LLM list label says it
    follows GitHub release tags, which can be a year behind the list's name
    (the 2025 list is tagged 2024).
  - `spike-hello.yml`, the phase 1 test workflow, is removed. Releases
    v0.0.1 and v0.0.2 still point at it by commit.
- Every job checks that the kit files it fetched are the workflow's own
  repository and commit, and fails if GitHub left either unnamed (review
  item F6). Without this, an empty name would fetch the project's own
  repository or the kit's newest commit and run it as the kit.

- Fixes from the second security audit (honest accidents that let a check
  pass while checking less):
  - The secret scan reads every text file's history even when a project's
    `.gitattributes` marks it as binary (`-diff`). A planted secret in such
    a file used to pass.
  - A yarn, pnpm or bun lockfile is reported as not checked even next to an
    npm lockfile, since npm audit reads only the npm one.
  - Access tests that were all skipped no longer count as having run.
  - New self-test plants cover these, plus a committed file that
    `.gitignore` lists (Semgrep already scanned it; the plant keeps it so).

- More fixes from the second security audit:
  - The pin check reads `pyproject.toml` `[project].dependencies`, so a
    library listed there with a range (`requests>=2`) fails.
  - A requirements file that another one includes still counts for the
    including file's second-package-source rule, even when it was checked
    on its own first.
  - Workflow keys written in quotes (`"uses":`, `"container":`) are checked.
  - The watcher's issue and RELEASING.md say to read the issue with
    `gh issue view <number> --json author,body`, which leaves out comments
    anyone could add on the public repository.
  - Not fixed, by the owner's choice (the kit is for the owner's own use):
    five leads that need someone deliberately cheating the checks (a fake
    job with the verdict's name, a pin to a fork-only commit, a shared npm
    cache between jobs, a deliberate `.gitleaksignore`, and the run
    summary's list of skip comments missing some spellings).

- Readable results: each checks job writes a plain-language section to the
  run's summary page, with every check as passed, found N (each item and
  where it is, plus what to do), couldn't check, or didn't run. The step
  only reports, so it never fails the job.

- One security score per run: the new `score.yml` workflow turns the code
  checks' and website scan's results into a score out of 100 (each passing
  check earns an equal share; a leaked secret, a library with a known hole,
  a failing access rule or a check that didn't run caps it at 49) and a
  checklist progress line, on the run's summary page. The project template
  gains a `score` job that calls it. Existing projects add that job to use
  it.

- The README's setup starts with asking Claude to set up the security kit
  (the secure-start skill), and says where results show up: the score and
  table on each run's summary page, and the security-report skill.

## v0.1.0 (2026-11-19), test release

- Shared checks (`scans.yml`): gitleaks, pip-audit, npm audit, Semgrep,
  a new exact-pin check, and the project's access-rule tests.
- Website scan (`site-scan.yml`): starts the app inside the job and runs a
  look-only ZAP baseline scan with the kit's rules.
- Self-test: six planted defects in a fixture app, each caught by its own
  check, and the clean app passes everything. Caught 6 of 6. Before the kit,
  the same scanners caught 3 of 6: no exact-pin check, no website scan, no
  access-rule check in CI.
- Templates: the workflow that calls the kit, Dependabot with a 7-day
  cooldown, the secret check before commits, FastAPI and Next.js header
  defaults, a threat model, an incident plan, a security policy and
  `security.txt`.
- Checklist version 0.1: 54 checks with sources and how each is checked.

## v0.0.1 and v0.0.2 (2026-11-19)

Phase 1 test releases (`spike-hello.yml`), used to prove that projects can
call the kit and that Dependabot sees new kit releases.
