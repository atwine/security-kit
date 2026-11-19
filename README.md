# security-kit

Shared security checks, templates and a checklist that my projects use, so
every project starts secure and stays current as security standards change.

**Status: work in progress. Not ready for use.** Versions below 1.0.0 are
test releases.

## What it will hold

- Shared GitHub checks that any project calls: leaked secrets, libraries
  with known holes, risky code patterns, and a look-only scan of the
  running site.
- Templates: a threat model, an incident plan, `security.txt`, Dependabot
  setup and safe default security headers.
- A versioned checklist drawn from the OWASP Application Security
  Verification Standard (Level 2), the OWASP Top 10, the OWASP API Security
  Top 10 and the OWASP Top 10 for LLM Applications, plus privacy basics.
  Each item says how it's checked.
- A monthly job that watches for new standards and newly exploited holes,
  and proposes updates to this kit.

## Licence

MIT. See [LICENSE](LICENSE).
