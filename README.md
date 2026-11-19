# security-kit

Shared security checks, templates and a checklist that my projects use, so
every project starts secure and stays current as security standards change.

**Status: test releases (0.x). Not ready for general use.**

## What's in it

| Part | What it does |
|---|---|
| [`.github/workflows/scans.yml`](.github/workflows/scans.yml) | Checks the code on every push: leaked secrets in the history (gitleaks), Python and JavaScript libraries with known holes (pip-audit, npm audit), risky code patterns (Semgrep), exact version pins ([`checks/pins.py`](checks/pins.py)), and the project's access-rule tests. |
| [`.github/workflows/site-scan.yml`](.github/workflows/site-scan.yml) | Starts the app inside the GitHub job and runs a look-only OWASP ZAP baseline scan. Missing protective headers, insecure cookies and open cross-site rules fail it ([`checks/zap-baseline.conf`](checks/zap-baseline.conf)). |
| [`templates/`](templates) | What a project copies: the workflow that calls the kit, Dependabot setup with a 7-day cooldown, the secret check before each commit, safe header defaults for FastAPI and Next.js, and a threat model, incident plan, security policy and `security.txt`. |
| [`checklist/CHECKLIST.md`](checklist/CHECKLIST.md) | 54 checks drawn from the OWASP Application Security Verification Standard 5.0, the OWASP Top 10:2025, the API Security Top 10 2023 and the Top 10 for LLM Applications 2025, plus privacy basics. Each says whether a kit check, a skill, kept evidence or an owner decision covers it. |
| [`watch/`](watch) | The monthly watcher ([`watch.yml`](.github/workflows/watch.yml)): looks for new versions of the scanners the kit pins, new OWASP editions, critical advisories for FastAPI, Starlette, Next.js and React, and actively exploited holes in those stacks, then opens one `kit-update` issue listing them. |

Both workflows load the kit's own scripts at the exact version the project
pinned, so a project on one release always runs that release's checks.

## How the kit proves itself

[`self-test.yml`](.github/workflows/self-test.yml) runs on every change. It
plants one known defect at a time into a small fixture app: a leaked token,
a library with known holes, risky code, an unpinned library, missing
headers, and a route with no access rule. Each defect must make its own
check fail, and the clean app must pass everything. The fake token is
generated during the run and never stored. The same check runs the
watcher's tests: a planted change in each source must be reported with a
source link, and a quiet month or a second run must propose nothing.

## Staying current

On the 1st of each month the watcher checks four sources, listed in
[`watch/sources.json`](watch/sources.json):

- new releases of the scanners the kit pins inside its workflows, which
  Dependabot can't see;
- new editions of the OWASP lists the checklist is built on;
- critical GitHub advisories for FastAPI, Starlette, Next.js and React;
- entries in CISA's list of actively exploited holes that name those
  stacks, Node.js, Python or PostgreSQL.

When something is new it opens one `kit-update` issue, each item with its
source link. It uses no AI and no secret, names each item only once, and
opens nothing in a quiet month. If a source can't be read, the run fails
instead of reporting "nothing changed". To act on an issue, ask Claude in a
session to draft the kit changes; they reach `main` through a pull request
([RELEASING.md](RELEASING.md)).

GitHub pauses scheduled jobs in a public repository after 60 days without
activity. If the watcher goes quiet for longer than a month, check the
Actions tab and turn it back on.

## Using it in a project

1. Copy [`templates/security.yml`](templates/security.yml) to
   `.github/workflows/security-scans.yml` and pin it to a release's full
   commit SHA. The `secure-start` skill in my skills repository does every
   step here.
2. Copy [`templates/dependabot.yml`](templates/dependabot.yml), so new kit
   releases arrive as update pull requests after the cooldown.
3. Work through [`checklist/CHECKLIST.md`](checklist/CHECKLIST.md).

## Changing the kit

`main` accepts changes only through pull requests whose self-test and
security checks pass, and release tags can't be moved or deleted. How a
version is released: [RELEASING.md](RELEASING.md).

## Licence

MIT. See [LICENSE](LICENSE).
