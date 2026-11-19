"""Decide a project's code checks: pass or fail, from GitHub's record of each check.

    NEEDS='<toJSON(needs)>' ASKED_REPORT_ONLY=... REPO=... KIT_REPO=... python -I checks/gate.py

scans.yml's deciding job runs this on a fresh machine, where none of the
project's code has run. It reads only the step outcomes GitHub recorded for
each check, prints a table, and exits 1 when the project fails.

Environment:
    NEEDS              the deciding job's toJSON(needs)
    ASKED_REPORT_ONLY  "true" when the caller set fail-on-findings: false
    REPO, KIT_REPO     github.repository and job.workflow_repository
"""

import json
import os
import sys


# Each checks job and the results it must report. Nothing else may appear:
# a result that is missing fails (GitHub drops a result whose text a step
# registered as a secret), and so does one the gate doesn't know.
CHECKS = {
    "read": ("secrets", "risky_code", "pins", "node_libraries"),
    "run": ("python_libraries", "access_rules"),
}
NOT_A_CHECK = {"evidence"}  # the kit's self-test reads it; never judged


def decide(needs: dict) -> tuple[list[str], list[str]]:
    """Return (problems, table rows) for the checks jobs in needs."""
    rows = ["| Check | Result |", "|---|---|"]
    problems = []
    for job in sorted(set(needs) - set(CHECKS)):
        problems.append(f"'{job}' isn't a checks job the gate knows.")
    for job, checks in CHECKS.items():
        data = needs.get(job)
        if data is None:
            problems.append(f"The checks job '{job}' is missing, so {', '.join(checks)} didn't run.")
            rows.extend(f"| {check} | no result |" for check in checks)
            continue
        if data.get("result") != "success":
            problems.append(f"The checks job '{job}' ended with '{data.get('result')}', so some checks may not have run.")
        outputs = data.get("outputs") or {}
        for unknown in sorted(set(outputs) - set(checks) - NOT_A_CHECK):
            problems.append(f"The checks job '{job}' reported '{unknown}', which isn't a check the gate knows.")
        for check in checks:
            outcome = outputs.get(check) or ""
            rows.append(f"| {check} | {'found something' if outcome == 'failure' else (outcome or 'no result')} |")
            if outcome == "failure":
                problems.append(f"{check} found something. Open its step in the '{job}' checks job for the details.")
            elif not outcome:
                problems.append(f"{check} has no result. A missing result counts as a failure: GitHub drops a result whose text a step registered as a secret.")
            elif outcome != "success":
                problems.append(f"{check} did not run ({outcome}).")
    return problems, rows


def main() -> int:
    problems, rows = decide(json.loads(os.environ.get("NEEDS") or "{}"))
    asked_report_only = os.environ.get("ASKED_REPORT_ONLY") == "true"
    report_only = asked_report_only and os.environ.get("REPO") == os.environ.get("KIT_REPO")
    table = "\n".join(rows)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(table + "\n")
    if asked_report_only and not report_only:
        print("::warning::fail-on-findings: false only applies to the kit's own self-test. This project's results still decide the check.")
    for problem in problems:
        print(("::notice::" if report_only else "::error::") + problem)
    return 0 if report_only or not problems else 1


if __name__ == "__main__":
    sys.exit(main())
