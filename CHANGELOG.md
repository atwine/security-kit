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
