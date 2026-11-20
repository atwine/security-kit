"""The self-test's verdict: compare what each check did with what must happen.

    NEEDS='<the self-test's toJSON(needs)>' python -I selftest/verdict.py

self-test.yml runs this on a fresh machine after every planted-defect job.
It prints a table, adds it to the run summary, and exits 1 when anything is
wrong.
"""

import json
import os
import re
import sys
from pathlib import Path

CODE_CHECKS = ("secrets", "risky_code", "pins", "node_libraries", "python_libraries", "access_rules")
SITE_CHECKS = ("site_headers", "site_policy")

# Planted defect -> (job, the check that must catch it, what that check's
# report must name to prove it caught the planted item). Each text must
# appear in the report; none holds a version Dependabot could change.
EXPECTED = {
    "secret": ("secret", "secrets", ("selftest/fixture-app/settings_local.py",)),
    "vulnerable-library": ("vulnerable-library", "python_libraries", ("urllib3==1.26.4",)),
    "node-library": ("node-library", "node_libraries", ("lodash (", "GHSA-")),
    "risky-code": ("risky-code", "risky_code", ("selftest/fixture-app/run_command.py",)),
    "unpinned-library": ("unpinned-library", "pins", ("selftest/fixture-app/requirements.txt", "`fastapi>=")),
    "unruled-route": ("unruled-route", "access_rules", ("/admin/export",)),
    # ZAP rule numbers, each followed by the space before the rule's name.
    "missing-headers": ("site-missing-headers", "site_headers", ("10038 ", "10020 ", "10021 ")),
    # Ways around the gate: each must still be caught by its check.
    "forge-verdict": ("forge-verdict", "secrets", ("selftest/fixture-app/settings_local.py",)),
    "mask-failure": ("mask-failure", "secrets", ("selftest/fixture-app/settings_local.py",)),
    "env-bypass": ("site-env-bypass", "site_headers", ("10038 ", "10020 ", "10021 ")),
    # Checks that used to pass without checking anything (group B).
    "npm-subfolder": ("npm-subfolder", "node_libraries", ("lodash (", "GHSA-")),
    "yarn-lockfile": ("yarn-lockfile", "node_libraries", ("not checked: selftest/fixture-app/yarn.lock",)),
    "pyproject-library": ("pyproject-library", "python_libraries", ("urllib3==1.26.4",)),
    "renamed-access-tests": ("renamed-access-tests", "access_rules", ("/admin/export",)),
    "missing-access-tests": ("missing-access-tests", "access_rules", ("not checked: selftest/fixture-app/ACCESS.md",)),
    "gitleaks-config": ("gitleaks-config", "secrets", ("selftest/fixture-app/settings_local.py",)),
    "semgrepignore": ("semgrepignore", "risky_code", ("selftest/fixture-app/run_command.py",)),
    "npmrc-registry": ("npmrc-registry", "node_libraries", ("lodash (", "GHSA-")),
    # Honest accidents from audit run 2 (PR K1).
    "gitattributes-secret": ("gitattributes-secret", "secrets", ("selftest/fixture-app/settings_local.py",)),
    "gitignored-risky-code": ("gitignored-risky-code", "risky_code", ("selftest/fixture-app/run_command.py",)),
    # Website rules ZAP can't check over plain HTTP (group D).
    "site-no-hsts": ("site-no-hsts", "site_policy", ("KIT-HSTS ",)),
    "site-no-referrer-permissions": ("site-no-referrer-permissions", "site_policy", ("KIT-REFERRER ", "KIT-PERMISSIONS ")),
    "site-insecure-cookie": ("site-insecure-cookie", "site_policy", ("KIT-COOKIE-SECURE ", "KIT-COOKIE-SAMESITE ")),
    "site-cors-wildcard": ("site-cors-wildcard", "site_policy", ("KIT-CORS ",)),
    "site-redirect-cookie": ("site-redirect-cookie", "site_policy", ("KIT-COOKIE-SECURE http://127.0.0.1:8000/welcome",)),
    # Loose pins the pin check missed (group E).
    "pin-included-file": ("pin-included-file", "pins", ("selftest/fixture-app/more.txt:1",)),
    "pin-workflow-image": ("pin-workflow-image", "pins", (".github/workflows/planted.yml", "python:3.12")),
    "pin-precommit-tag": ("pin-precommit-tag", "pins", ("selftest/fixture-app/.pre-commit-config.yaml", "v8.30.1")),
    # The environment-line bypass again, aimed at the kit's own check.
    "env-bypass-policy": ("site-env-bypass-policy", "site_policy", ("KIT-HSTS ",)),
    "hidden-folder-code": ("hidden-folder-code", "risky_code", ("selftest/fixture-app/.security-kit/run_command.py",)),
    "env-folder-pin": ("env-folder-pin", "pins", ("selftest/fixture-app/env/requirements.txt",)),
}

# Jobs that run unit tests, and how the table names them.
UNIT_TESTS = {
    "watcher": "Watcher tests (planted changes reported, quiet runs silent)",
    "self-test-rules": "Tests of the self-test's verdict and report readers",
    "watcher-recent": "The watcher succeeded in the last 40 days",
}


CLEAN_JOBS = {"clean": CODE_CHECKS, "site-clean": SITE_CHECKS}
# score.yml jobs and the range their score must fall in.
SCORE_JOBS = {"score-clean": (100, 100), "score-secret": (0, 49)}
WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
SOURCES = Path(__file__).resolve().parents[1] / "watch" / "sources.json"
IMAGES = ("semgrep", "zap")  # the scanners the kit runs as tag@digest images


def pinned_tags() -> dict:
    """The version tag the kit pins next to each scanner image's digest, found the way the watcher finds it."""
    scanners = json.loads(SOURCES.read_text(encoding="utf-8"))["scanners"]
    tags = {}
    for tool in IMAGES:
        spec = scanners[tool]
        found = re.search(spec["pin"], (SOURCES.parents[1] / spec["file"]).read_text(encoding="utf-8"))
        tags[tool] = found.group(1) if found else ""
    return tags


def version_problems(pinned: dict, reported: dict) -> list[str]:
    """Docker runs the digest, not the tag, so the version that ran must match the tag."""
    problems = []
    for tool, tag in pinned.items():
        ran = reported.get(tool)
        if not ran:
            problems.append(f"{tool}: the clean run reported no version, so the pinned tag {tag} can't be checked against the image that ran")
        elif ran != tag:
            problems.append(f"{tool}: the workflow pins tag {tag}, but the image that ran is {ran}; the tag and digest disagree")
    return problems


def checks_of(job: str) -> tuple[str, ...]:
    return SITE_CHECKS if job.startswith("site-") else CODE_CHECKS


def short(items: list[str], limit: int = 2) -> str:
    shown = "; ".join(item[:120] for item in items[:limit])
    return shown + (f" (and {len(items) - limit} more)" if len(items) > limit else "")


def decide(needs: dict) -> tuple[list[str], list[str]]:
    """Return (problems, report lines) for one self-test run.

    The run passes only when every job finished; the clean app passes every
    check with nothing reported; each planted defect fails its own check and
    that check's report names the planted item; and in each defect run every
    other check passes with nothing reported.
    """
    problems = []
    known = set(CLEAN_JOBS) | {job for job, _, _ in EXPECTED.values()} | set(UNIT_TESTS) | set(SCORE_JOBS)
    for job in sorted(set(needs) - known):
        problems.append(f"{job}: the verdict doesn't know this job; add it to EXPECTED in selftest/verdict.py")

    def read(job: str):
        """(results, evidence) of a scan job, or None when the job is missing or unreadable."""
        if job not in needs:
            problems.append(f"{job}: the job is missing from the self-test")
            return None
        if needs[job].get("result") != "success":
            problems.append(f"{job}: the job ended with '{needs[job].get('result')}', expected 'success'")
        outputs = needs[job].get("outputs") or {}
        try:
            # scans.yml reports evidence from each of its checks jobs
            # (evidence-read, evidence-run); site-scan.yml as one (evidence).
            evidence = {}
            for name, raw in sorted(outputs.items()):
                if name.startswith("evidence"):
                    part = json.loads(raw or "{}")
                    versions = {**evidence.get("_versions", {}), **part.get("_versions", {})}
                    evidence.update(part)
                    if versions:
                        evidence["_versions"] = versions
            return json.loads(outputs.get("results") or "{}"), evidence
        except ValueError:
            problems.append(f"{job}: its results or evidence aren't readable JSON")
            return None

    def must_pass(job: str, check: str, results: dict, evidence: dict, who: str) -> None:
        outcome = results.get(check) or "no result"
        if outcome != "success":
            problems.append(f"{who}: {check} gave '{outcome}', expected 'success'")
        elif evidence.get(check):
            problems.append(f"{who}: {check} passed but reported {short(evidence[check])}")

    reported = {}
    for job, checks in CLEAN_JOBS.items():
        data = read(job)
        if data:
            for check in checks:
                must_pass(job, check, *data, who=f"clean app ({job})")
            reported.update(data[1].get("_versions") or {})
    problems.extend(version_problems(pinned_tags(), reported))

    rows = []
    for defect, (job, check, planted) in EXPECTED.items():
        data = read(job)
        if data is None:
            rows.append(f"| {defect} | {check} | NO RESULT | |")
            continue
        results, evidence = data
        outcome = results.get(check) or "no result"
        found = evidence.get(check) or []
        proof = [item for item in found if any(name in item for name in planted)]
        unnamed = [name for name in planted if not any(name in item for item in found)]
        if outcome == "failure" and not unnamed:
            verdict = "CAUGHT"
        elif outcome == "failure":
            verdict = "NOT PROVEN"
            problems.append(
                f"{defect}: {check} failed, but its report doesn't name {', '.join(unnamed)}"
                + (f"; it reported {short(found)}" if found else "; it reported nothing")
            )
        else:
            verdict = f"MISSED ({outcome})"
            problems.append(f"{defect}: {check} gave '{outcome}', expected 'failure'")
        for other in checks_of(job):
            if other != check:
                must_pass(job, other, results, evidence, who=f"{defect} (only {check} should fail)")
        rows.append(f"| {defect} | {check} | {verdict} | {short(proof).replace('|', '/')} |")

    caught = sum("| CAUGHT |" in row for row in rows)
    lines = [
        "| Planted defect | Check | Result | What the check's report named |",
        "|---|---|---|---|",
        *rows,
        "",
        f"Caught {caught} of {len(EXPECTED)}.",
    ]
    for job, (low, high) in SCORE_JOBS.items():
        data = needs.get(job)
        raw = ((data or {}).get("outputs") or {}).get("score", "")
        if data is None or data.get("result") != "success" or not str(raw).isdigit():
            problems.append(f"{job}: no score (job result '{(data or {}).get('result', 'missing')}')")
        elif not low <= int(raw) <= high:
            problems.append(f"{job}: scored {raw}, expected {low} to {high}")
        else:
            lines.append(f"{job}: scored {raw}, as expected.")
    for job, label in UNIT_TESTS.items():
        result = needs.get(job, {}).get("result", "missing")
        if result != "success":
            problems.append(f"{job}: its tests gave '{result}', expected 'success'")
        lines.append(f"{label}: {result}.")
    lines.append(
        f"{len(problems)} problem(s), listed as errors below."
        if problems
        else "Every job finished, the clean app reported nothing, and every other check passed in each defect run."
    )
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
