# Threat model: PROJECT NAME

One page: what's worth protecting, who might go after it, how, and what
stops them. Re-read it whenever a feature adds a new kind of data, a new
kind of user or a new outside service. Last reviewed: DATE, by NAME.

## What's worth protecting

| What | Why it matters | Where it lives |
|---|---|---|
| e.g. users' messages | personal and sensitive | database, the AI provider |
| e.g. staff accounts | can read everyone's data | sign-in service |
| e.g. the AI budget | a script can run it up | AI provider key |

## Who uses it

List each kind of user (members, guests, staff, admins) and each outside
service the app sends data to (hosting, sign-in, AI, email).

## Who might attack, how, and what stops them

The STRIDE list makes sure nothing is skipped. It asks whether someone could:
- **S**poof: pretend to be someone else;
- **T**amper: change data they shouldn't;
- **R**epudiate: deny something they did;
- **I**nformation disclosure: see data they shouldn't;
- **D**enial of service: stop the service or run up its costs;
- **E**levation of privilege: gain powers they shouldn't have.

| Threat | Example | What stops it today | Proof (test, setting, check) |
|---|---|---|---|
| Information disclosure | a user changes an ID in the address and reads another user's data | access rules on every route | `ACCESS.md` and its tests |
| Spoofing | someone guesses a staff password | lockout after 3 tries; two-step login for admins | login tests |
| Denial of service | a script sends thousands of AI requests | rate limits; a monthly spending cap | rate-limit test; provider setting |
| Tampering | a malicious library update | exact version pins; 7-day Dependabot cooldown | security-kit `pins` check |
| ... | | | |

## Accepted risks

| Risk | Why it's accepted | Who accepted it | When | Review by |
|---|---|---|---|---|
| | | | | |

## Not covered here

Logic mistakes specific to this app, and legal and privacy decisions: see
the project's own tests, its privacy notice and its launch check.
