# Incident plan: PROJECT NAME

What to do when something goes wrong: a leaked key, a data leak, an outage,
or a report of a security hole. Keep it short enough to follow under stress.
Last reviewed: DATE, by NAME.

## Who decides

| Role | Name | How to reach them | Backup |
|---|---|---|---|
| Decides what to do | | | |
| Does the technical steps | | | |
| Speaks to users, partners and regulators | | | |

## The first hour

1. **Write down** what was seen, when, and by whom. Keep the evidence:
   logs, screenshots, the report. Don't delete anything yet.
2. **Stop the harm.** Pick the smallest step that does it:
   - Leaked key or token: revoke it with the provider, then replace it in
     the hosting settings and redeploy. Removing it from the code is not
     enough; it stays in git history.
   - Someone is inside an account: end that account's sessions and reset
     its password; for staff, end every staff session.
   - Data is leaking through the app: take the affected feature or the
     whole app offline (HOW: e.g. the hosting dashboard's "remove" or
     "sleep" button) and put up the maintenance page.
3. **Tell the person who decides**, even if it might be a false alarm.

## The first day

- Work out what was reached: which data, whose, between which times. The
  hosting logs, the database's audit tables and the provider dashboards
  are where to look (list them here: ...).
- Fix the cause, with a test that fails before the fix.
- Decide who must be told and by when. Data protection law, research
  ethics approvals and contracts can set deadlines. Write the deadlines
  that apply to this project here, from the people responsible for them:
  ...

## Afterwards

- A short write-up: what happened, why, what changed, and how the change
  is checked. Add the lesson to the project's threat model.
- Check this plan still matches reality, and update it.

## Contacts

| Service | What it holds | How to reach its security team |
|---|---|---|
| Hosting | | |
| Sign-in | | |
| AI provider | | |
