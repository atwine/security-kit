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
- The gate can no longer be faked by the project it checks (review group A).
  Each workflow now has a second job that decides pass or fail on a fresh
  machine from GitHub's record of each check. It keeps the old check names,
  "Security checks (security-kit)" and "Website scan (security-kit, ZAP
  baseline)", so existing branch protection still points at the deciding
  job. The kit's files move out of the project's folder before any project
  code runs, so Semgrep no longer needs to exclude a `.security-kit` folder.
  Steps that run project code come last. The website scan prepares its rules
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
- `scans.yml` and `site-scan.yml` have a new `evidence` output. It's filled
  only in the kit's own repository, for the self-test, and never decides a
  project's verdict.
- The code checks' verdict judges every output of the checks job except
  `evidence`, so a check added later is judged too, and it fails when the
  checks job reported nothing.

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
