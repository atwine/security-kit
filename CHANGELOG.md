# Changelog

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
