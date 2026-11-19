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


def decide(needs: dict) -> tuple[list[str], list[str]]:
    """Return (problems, table rows) for the checks jobs in needs."""
    rows = ["| Check | Result |", "|---|---|"]
    problems = []
    for job, data in sorted(needs.items()):
        results = {name: outcome for name, outcome in (data.get("outputs") or {}).items() if name != "evidence"}
        for name, outcome in sorted(results.items()):
            rows.append(f"| {name} | {'found something' if outcome == 'failure' else (outcome or 'no result')} |")
            if outcome == "failure":
                problems.append(f"{name} found something. Open its step in the checks job for the details.")
            elif outcome != "success":
                problems.append(f"{name} did not run ({outcome or 'no result'}).")
        if data.get("result") != "success":
            problems.append(f"The checks job '{job}' ended with '{data.get('result')}', so some checks may not have run.")
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
