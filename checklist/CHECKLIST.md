# Security checklist

**Checklist version 0.2** (the next security-kit release). The checks a project passes
before real people use it, and keeps passing afterwards.

Each item says how it's checked:

- **AUTO**: a kit check does it on every push (`scans.yml` or `site-scan.yml`).
- **SKILL**: a Claude Code skill sets it up or checks it (for example `access-guard`).
- **EVIDENCE**: a person keeps proof: a file, a test, a screenshot or a setting.
- **DECISION**: the project owner decides, usually with legal, ethics or partner input.

Sources are named by list and chapter:

- `ASVS V1`–`V17`: OWASP Application Security Verification Standard 5.0 chapters.
- `A01`–`A10`: OWASP Top 10:2025.
- `API1`–`API10`: OWASP API Security Top 10 2023.
- `LLM01`–`LLM10`: OWASP Top 10 for LLM Applications 2025.
- `ASI01`–`ASI10`: OWASP Top 10 for Agentic Applications 2026.

They point to the chapter or list entry, not to single requirement numbers.
The target for an app holding personal data is ASVS Level 2. Sensitive data
(health, children, money) justifies Level 3 for login, access control and
data protection.

## A. Code and libraries

| ID | Check | How | Sources |
|---|---|---|---|
| SK-01 | No secrets (keys, tokens, passwords) in the code or its git history; a secret check runs before every commit | AUTO `secrets` · pre-commit gitleaks | ASVS V13, A02 |
| SK-02 | No libraries with published security holes. Audits can't see a copy a framework bundles inside itself (Next.js bundles React's server code), so also follow the framework's own advisories and update it when it ships a fixed copy | AUTO `python_libraries`, `node_libraries` · EVIDENCE the framework's advisories followed | A03, ASVS V15 |
| SK-03 | Every library pinned to one exact version (hashes where possible), JavaScript lockfiles committed, GitHub actions pinned to full commit SHAs | AUTO `pins` | A03, LLM03 |
| SK-04 | Dependabot proposes updates to the integration branch, with a 7-day cooldown | EVIDENCE `.github/dependabot.yml` | A03 |
| SK-05 | Every new library is checked before it's added: it exists, it's the real one, and it's maintained (AI tools sometimes invent package names) | EVIDENCE pull request review | A03 |
| SK-06 | No risky code patterns (injection, unsafe deserialisation, weak crypto, shell commands built from input) | AUTO `risky_code` | A05, ASVS V1 |
| SK-07 | The database is reached only through the ORM or parameterised queries | AUTO `risky_code` (partly) · EVIDENCE review | A05, ASVS V1 |
| SK-08 | Every input is validated on the server with a typed model; responses return only the fields the caller may see | EVIDENCE review and tests | ASVS V2, API3 |
| SK-09 | Errors shown to users are generic; details go to the server log only | EVIDENCE a test or `curl` of a bad request | A10, ASVS V16 |

## B. Access and login

| ID | Check | How | Sources |
|---|---|---|---|
| SK-10 | Written rules for who may see and change what (`ACCESS.md`) | SKILL `access-guard` | A01, API1, API5 |
| SK-11 | Every route is covered by an access-rule test; a new route without a rule fails the build | AUTO `access_rules` | A01, API1 |
| SK-12 | Nobody reaches another person's records by changing an ID or a field | SKILL `access-guard` tests | API1, API3 |
| SK-13 | Login comes from a maintained library or service; no hand-written cryptography | EVIDENCE review | A07, ASVS V6, ASVS V11 |
| SK-14 | Passwords stored with a slow password hash (bcrypt or argon2) | EVIDENCE test | A04, ASVS V6 |
| SK-15 | Login and sign-up are rate-limited, with lockout after repeated failures | EVIDENCE test | A07, ASVS V6, API4 |
| SK-16 | Two-step login for admins and anyone who can read sensitive data | EVIDENCE setting and test | A07, ASVS V6 |
| SK-17 | Session cookies are HttpOnly, Secure and SameSite, expire, and sign-out ends the session everywhere | AUTO `site_headers` (cookie flags) · EVIDENCE test | ASVS V7 |
| SK-18 | Requests that change data and rely on cookies are protected against cross-site request forgery | EVIDENCE test | ASVS V3, ASVS V4 |

## C. Running in public

| ID | Check | How | Sources |
|---|---|---|---|
| SK-19 | HTTPS only; plain HTTP redirects to HTTPS | EVIDENCE `curl -I http://...` | ASVS V12 |
| SK-20 | Protective headers on every response: Content-Security-Policy, anti-clickjacking, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security | AUTO `site_headers` | A02, ASVS V3 |
| SK-21 | The Content-Security-Policy blocks, not just reports, and allows only the sources the site uses | AUTO `site_headers` (warns on weak directives) · EVIDENCE Mozilla Observatory | ASVS V3 |
| SK-22 | Cross-site access (CORS) lists exact origins, never `*` | AUTO `site_headers` · EVIDENCE review | A02, API8 |
| SK-23 | API documentation, debug pages and test routes are off in production | EVIDENCE `curl` of each | A02, API9 |
| SK-24 | Development servers listen on 127.0.0.1 only | EVIDENCE review | A02 |
| SK-25 | Public and paid endpoints are rate-limited, and paid outside services have a spending cap | EVIDENCE test and provider setting | API4, API6, LLM10 |
| SK-26 | File uploads have a size limit, a type check and a cleaned name, and are stored outside any publicly served folder | EVIDENCE test | ASVS V5 |
| SK-27 | Test and staging environments never use production data | EVIDENCE hosting settings | A02 |
| SK-28 | A current list of every deployed service, address, environment and outside provider | EVIDENCE a document | API9, API10 |

## D. AI features

| ID | Check | How | Sources |
|---|---|---|---|
| SK-29 | Safety rules that matter run outside the model, so a tricked model can't switch them off | EVIDENCE review and tests | LLM01 |
| SK-30 | A versioned jailbreak and prompt-injection test set runs before any release that changes the prompt, the model or the safety code | EVIDENCE test results | LLM01, LLM07, LLM09 |
| SK-31 | No secrets or other people's data in prompts; the system prompt is treated as public | EVIDENCE review | LLM02, LLM07 |
| SK-32 | The AI provider is set to not train on or keep conversations, as the project's privacy rules require | EVIDENCE provider setting | LLM02 |
| SK-33 | AI output is treated as untrusted: rendered safely, and the Content-Security-Policy stops anything it injects | AUTO `site_headers` (partly) · EVIDENCE test | LLM05 |
| SK-34 | AI tools and agents get only the permissions they need; consequential actions need a person's approval | EVIDENCE review | LLM06, ASI02, ASI03 |
| SK-35 | Models and embedding models are pinned to a fixed version or revision | EVIDENCE review | LLM03, ASI04 |
| SK-36 | AI use is limited per person and per address, with a monthly spending cap | EVIDENCE test and provider setting | LLM10 |
| SK-37 | A safety and accuracy evaluation set, reviewed by a domain expert, for high-stakes topics | EVIDENCE results | LLM09 |

## E. Watching and recovering

| ID | Check | How | Sources |
|---|---|---|---|
| SK-38 | Logs contain no personal data, secrets or message text | EVIDENCE a log scan | A09, ASVS V16 |
| SK-39 | Someone is alerted when the service is down or failing | EVIDENCE a tested alert | A09 |
| SK-40 | Security events are logged and noticed: repeated lockouts, admin access to personal data, permission changes | EVIDENCE logs and alert | A09, ASVS V16 |
| SK-41 | Automatic backups, stored separately and encrypted, with a restore actually tried | EVIDENCE restore record | ASVS V14 |
| SK-42 | An incident plan: who decides, how to revoke keys and sessions, how to take the service offline, who must be told | EVIDENCE `INCIDENT.md` (template) | A09 |
| SK-43 | A way for outsiders to report a security hole | EVIDENCE `SECURITY.md` and `/.well-known/security.txt` (templates) | (RFC 9116) |
| SK-44 | A threat model, re-read when a feature adds new data, users or services | EVIDENCE `THREAT-MODEL.md` (template) | A06 |

## F. Data and privacy

| ID | Check | How | Sources |
|---|---|---|---|
| SK-45 | A list of the personal data held: what, why, where, and which outside services receive it | EVIDENCE a document | ASVS V14 |
| SK-46 | How long each kind of data is kept, and what deletes it | DECISION, then EVIDENCE code or job | ASVS V14 |
| SK-47 | People can get a copy of their data and have it deleted, as the applicable law and ethics approvals require | DECISION, then EVIDENCE test | ASVS V14 |
| SK-48 | A privacy notice names every outside service that receives personal data | DECISION | ASVS V14 |
| SK-49 | Where data is stored, and any transfer abroad, is decided with whoever is legally responsible | DECISION | ASVS V14 |
| SK-50 | Sensitive data is encrypted at rest (database and backups) | EVIDENCE provider setting | A04, ASVS V14 |

## G. Before each production release

| ID | Check | How | Sources |
|---|---|---|---|
| SK-51 | Every change to production had a code review and a security review | EVIDENCE pull request | A06 |
| SK-52 | A launch check passed within the last 30 days | SKILL `launch-check` (a release gate is planned) | |
| SK-53 | For apps holding sensitive data: an independent penetration test, or a written decision to launch without one | DECISION | |
| SK-54 | A full security audit before the first release and every three months | EVIDENCE audit report | |
