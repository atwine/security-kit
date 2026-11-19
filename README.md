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

Both workflows load the kit's own scripts at the exact version the project
pinned, so a project on one release always runs that release's checks.

## How the kit proves itself

[`self-test.yml`](.github/workflows/self-test.yml) runs on every change. It
plants one known defect at a time into a small fixture app: a leaked token,
a library with known holes, risky code, an unpinned library, missing
headers, and a route with no access rule. Each defect must make its own
check fail, and the clean app must pass everything. The fake token is
generated during the run and never stored.

## Using it in a project

1. Copy [`templates/security.yml`](templates/security.yml) to
   `.github/workflows/security-scans.yml` and pin it to a release's full
   commit SHA. The `secure-start` skill in my skills repository does every
   step here.
2. Copy [`templates/dependabot.yml`](templates/dependabot.yml), so new kit
   releases arrive as update pull requests after the cooldown.
3. Work through [`checklist/CHECKLIST.md`](checklist/CHECKLIST.md).

## Licence

MIT. See [LICENSE](LICENSE).
