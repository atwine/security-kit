"""The self-test's verdict: compare what each check did with what must happen.

    NEEDS='<the self-test's toJSON(needs)>' python -I selftest/verdict.py

self-test.yml runs this on a fresh machine after every planted-defect job.
It prints a table, adds it to the run summary, and exits 1 when anything is
wrong.
"""

import json
import os
import sys

CODE_CHECKS = ("secrets", "risky_code", "pins", "node_libraries", "python_libraries", "access_rules")
SITE_CHECKS = ("site_headers",)

# Planted defect -> (job, the check that must catch it, what that check's
# report must name to prove it caught the planted item).
EXPECTED = {
    "secret": ("secret", "secrets", ("selftest/fixture-app/settings_local.py",)),
    "vulnerable-library": ("vulnerable-library", "python_libraries", ("urllib3==1.26.4",)),
    "node-library": ("node-library", "node_libraries", ("lodash",)),
    "risky-code": ("risky-code", "risky_code", ("selftest/fixture-app/run_command.py",)),
    "unpinned-library": ("unpinned-library", "pins", ("fastapi>=0.165.0",)),
    "unruled-route": ("unruled-route", "access_rules", ("/admin/export",)),
    "missing-headers": ("site-missing-headers", "site_headers", ("10038", "10020", "10021")),
    # Ways around the gate: each must still be caught by its check.
    "forge-verdict": ("forge-verdict", "secrets", ("selftest/fixture-app/settings_local.py",)),
    "hidden-folder-code": ("hidden-folder-code", "risky_code", ("selftest/fixture-app/.security-kit/run_command.py",)),
    "env-folder-pin": ("env-folder-pin", "pins", ("selftest/fixture-app/env/requirements.txt",)),
}

# Jobs that run unit tests, and how the table names them.
UNIT_TESTS = {
    "watcher": "Watcher tests (planted changes reported, quiet runs silent)",
    "self-test-rules": "Tests of the self-test's verdict and report readers",
}


def decide(needs: dict) -> tuple[list[str], list[str]]:
    """Return (problems, report lines) for one self-test run."""

    def results(job):
        raw = needs[job].get("outputs", {}).get("results") or "{}"
        return json.loads(raw)

    problems, rows = [], []
    for job in ("clean", "site-clean"):
        found = results(job)
        if not found:
            problems.append(f"{job}: no results (the job didn't finish)")
        for check, outcome in found.items():
            if outcome != "success":
                problems.append(f"clean app: {check} gave {outcome}, expected success")
    for defect, (job, check, _planted) in EXPECTED.items():
        outcome = results(job).get(check)
        if outcome is None:
            verdict = "not built yet"
        elif outcome == "failure":
            verdict = "CAUGHT"
        else:
            verdict = f"MISSED ({outcome})"
            problems.append(f"{defect}: {check} gave {outcome}, expected failure")
        rows.append(f"| {defect} | {check} | {verdict} |")
    caught = sum("CAUGHT" in row for row in rows)
    lines = ["| Planted defect | Check | Result |", "|---|---|---|", *rows, "", f"Caught {caught} of {len(rows)}."]
    for job, label in UNIT_TESTS.items():
        result = needs[job]["result"]
        if result != "success":
            problems.append(f"{job}: its tests gave {result}, expected success")
        lines.append(f"{label}: {result}.")
    return problems, lines


def main() -> int:
    problems, lines = decide(json.loads(os.environ["NEEDS"]))
    report = "\n".join(lines)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(report + "\n")
    for problem in problems:
        print(f"::error::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
