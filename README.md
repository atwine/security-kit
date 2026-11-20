# security-kit

Shared security checks, templates and a checklist that my projects use, so
every project starts secure and stays current as security standards change.

**Status: test releases (0.x). Not ready for general use.**

## What's in it

| Part | What it does |
|---|---|
| [`.github/workflows/scans.yml`](.github/workflows/scans.yml) | Checks the code on every push: leaked secrets in the history (gitleaks), Python and JavaScript libraries with known holes (pip-audit, npm audit), risky code patterns (Semgrep), exact version pins ([`checks/pins.py`](checks/pins.py)), and the project's access-rule tests. |
| [`.github/workflows/site-scan.yml`](.github/workflows/site-scan.yml) | Starts the app inside the GitHub job and runs a look-only OWASP ZAP baseline scan. Missing protective headers and cookies without HttpOnly fail it ([`checks/zap-baseline.conf`](checks/zap-baseline.conf)). The kit's own check ([`checks/site_policy.py`](checks/site_policy.py)) covers what ZAP can't see over plain HTTP: HSTS, Referrer-Policy, Permissions-Policy, cookie Secure and SameSite flags, and CORS. |
| [`templates/`](templates) | What a project copies: the workflow that calls the kit, Dependabot setup with a 7-day cooldown, the secret check before each commit, safe header defaults for FastAPI and Next.js, and a threat model, incident plan, security policy and `security.txt`. |
| [`checklist/CHECKLIST.md`](checklist/CHECKLIST.md) | 54 checks drawn from the OWASP Application Security Verification Standard 5.0, the OWASP Top 10:2025, the API Security Top 10 2023 and the Top 10 for LLM Applications 2025, plus privacy basics. Each says whether a kit check, a skill, kept evidence or an owner decision covers it. |
| [`watch/`](watch) | The monthly watcher ([`watch.yml`](.github/workflows/watch.yml)): looks for new versions of the scanners the kit pins, new OWASP editions, critical advisories for FastAPI, Starlette, Next.js and React, and actively exploited holes in those stacks, then opens one `kit-update` issue listing them. |

Both workflows load the kit's own scripts at the exact version the project
pinned, so a project on one release always runs that release's checks.

The code checks run in two jobs. gitleaks, Semgrep, the pin check and npm
audit run on a machine where none of the project's code ever runs. pip-audit
(which builds the project's Python packages) and the access-rule tests run
on another, where that code can still interfere with those two checks.
GitHub records how each check step ended, and a third job decides pass or
fail on a fresh machine from that record ([`checks/gate.py`](checks/gate.py)).
It expects a fixed list of results, and a missing or unknown one fails:
GitHub silently drops a result whose text a step registered as a secret.
Each job fetches the kit before the project, so a project folder can't be
emptied by the kit's own fetch.

A check that can't look counts as failed. [`checks/inventory.py`](checks/inventory.py)
finds every npm lockfile, requirements file, pyproject project and ACCESS.md
the project tracks. Something no check can read, such as a yarn lockfile or
an ACCESS.md with no access tests, fails that check as "not checked". The
kit uses its own scanner settings: a project's `.gitleaks.toml`,
`.gitleaksignore`, `.semgrepignore` and `.npmrc` are ignored, and npm audit
always asks the public registry. Inline `gitleaks:allow` and `nosemgrep`
comments still skip their own line, and the run summary lists each one in
the current files.

The website scan has to run the project's app in the same job as ZAP. Its
later steps ignore the environment lines that would switch off bash or
redirect the loader and docker. A deliberately malicious app could still
interfere with that scan, for example by rewriting the rules file between
the check and the scan; see the note at the top of
[`site-scan.yml`](.github/workflows/site-scan.yml).

## How the kit proves itself

[`self-test.yml`](.github/workflows/self-test.yml) runs on every change. It
plants one known defect at a time into a small fixture app: a leaked token,
a Python library and a JavaScript library with known holes, risky code, an
unpinned library, missing headers, and a route with no access rule. Three
more try to get around the gate: a project file that forges the verdict,
risky code in a folder named like the kit's own, and a loose pin in a folder
named `env`. Two more try to hide a result: project code that registers the
word "failure" as a secret so GitHub drops failed results, and an app that
writes `SHELLOPTS=noexec` into the environment of the website scan's later
steps.

Each defect must make its own check fail, and that check's own report must
name the planted item, so a crash or an unrelated error doesn't count as a
catch. Every other check must still pass in that run. The clean app must
pass everything with nothing reported, and a missing result fails the run.
The rules live in [`selftest/verdict.py`](selftest/verdict.py), which has its
own tests. The fake token is generated during the
run and never stored. The
same check runs the watcher's tests: a planted change in each source must be
reported with a source link, and a quiet month or a second run must propose
nothing.

## Staying current

On the 1st of each month the watcher checks four sources, listed in
[`watch/sources.json`](watch/sources.json):

- new releases of the scanners the kit pins inside its workflows, which
  Dependabot can't see;
- new editions of four of the five OWASP lists the checklist cites. The
  fifth, the Top 10 for Agentic Applications, has no release feed, so
  [RELEASING.md](RELEASING.md) checks it by hand before each release;
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
2. In the project's branch protection, require the two checks that decide
   pass or fail. GitHub puts the name of the calling job in front, so with
   the template they are "code / Security checks (security-kit)" and
   "website / Website scan (security-kit, ZAP baseline)".
3. Copy [`templates/dependabot.yml`](templates/dependabot.yml), so new kit
   releases arrive as update pull requests after the cooldown.
4. Work through [`checklist/CHECKLIST.md`](checklist/CHECKLIST.md).

Call the workflows from `push` or `pull_request`. They refuse
`pull_request_target` and `workflow_run`, which check out the base branch
instead of the change. The `fail-on-findings` and `self-test-defect` inputs
are for the kit's own self-test: a project can't use them to turn findings
into a pass.

## Changing the kit

`main` accepts changes only through pull requests whose self-test and
security checks pass, and release tags can't be moved or deleted. How a
version is released: [RELEASING.md](RELEASING.md).

## Licence

MIT. See [LICENSE](LICENSE).
