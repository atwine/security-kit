"""One security score for a project run, and how far the checklist is covered.

    CODE='<code results JSON>' WEBSITE='<website results JSON or empty>' python score.py <CHECKLIST.md>

CODE and WEBSITE are the `results` outputs of scans.yml and site-scan.yml:
check name -> GitHub's record of that check step (success or failure).
WEBSITE is empty when the project has no website scan.

The score is out of 100: each check that passed earns an equal share. A
serious problem caps it at 49, so one serious problem can't hide behind a
high number: a leaked secret, a library with a known hole, a failing access
rule, or any check that didn't run. Other findings cost points but don't cap.

Prints Markdown for the run's summary page and writes `score=<n>` to
GITHUB_OUTPUT when it is set. It only reports, so it always exits 0.
Standard library only.
"""

import json
import os
import re
import sys
from pathlib import Path

CODE_CHECKS = ("secrets", "risky_code", "pins", "node_libraries", "python_libraries", "access_rules")
SITE_CHECKS = ("site_headers", "site_policy")
SERIOUS = {
    "secrets": "Leaked secrets",
    "python_libraries": "Python libraries with known holes",
    "node_libraries": "JavaScript libraries with known holes",
    "access_rules": "Access rules",
}
NAMES = {
    "secrets": "Leaked secrets",
    "risky_code": "Risky code patterns",
    "pins": "Pinned versions",
    "node_libraries": "JavaScript libraries",
    "python_libraries": "Python libraries",
    "access_rules": "Access rules",
    "site_headers": "Website scan (ZAP)",
    "site_policy": "Website rules",
}
CAP = 49
ITEM = re.compile(r"^\|\s*(SK-\d+)\s*\|[^|]*\|([^|]*)\|", re.M)
AUTO = re.compile(r"AUTO\s+([^·]*)")
NAMED = re.compile(r"`([a-z_]+)`")


def _read(text: str, checks: tuple[str, ...]) -> dict[str, str] | None:
    """The outcome of each expected check, or None when the results can't be read."""
    try:
        data = json.loads(text) if text else None
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return {check: str(data.get(check) or "") for check in checks}


def results(code: str, website: str) -> dict[str, str] | None:
    """Every check's outcome for this run; None when the code checks didn't report."""
    found = _read(code, CODE_CHECKS)
    if found is None:
        return None
    if not website.strip():
        return found  # no website scan in this project: only the code checks count
    site = _read(website, SITE_CHECKS)
    return {**found, **(site or {check: "" for check in SITE_CHECKS})}


def score(code: str, website: str) -> tuple[int, list[str]]:
    """(score out of 100, why it was capped)."""
    outcomes = results(code, website)
    if outcomes is None:
        return 0, ["The code checks didn't report any results, so nothing can be scored."]
    passed = sum(outcome == "success" for outcome in outcomes.values())
    points = round(100 * passed / len(outcomes))
    reasons = [f"{SERIOUS[check]} found something." for check in SERIOUS if outcomes.get(check) == "failure"]
    reasons += [f"{NAMES[check]} didn't run." for check, outcome in outcomes.items() if outcome not in ("success", "failure")]
    return (min(points, CAP) if reasons else points), reasons


def progress(checklist: str, outcomes: dict[str, str]) -> tuple[int, int, int]:
    """(checklist items the kit checks this run, how many passed, items that need the owner)."""
    automatic = passed = manual = 0
    for _, how in ITEM.findall(checklist):
        auto = AUTO.search(how)
        checks = NAMED.findall(auto.group(1)) if auto else []
        if not checks:
            manual += 1
            continue
        if any(check not in outcomes for check in checks):
            continue  # its check isn't part of this run (no website scan)
        automatic += 1
        passed += all(outcomes[check] == "success" for check in checks)
    return automatic, passed, manual


def report(code: str, website: str, checklist: str) -> tuple[str, int]:
    points, reasons = score(code, website)
    lines = [f"## Security score: {points} out of 100", ""]
    if reasons:
        lines += [f"Capped at {CAP}, because:", ""] + [f"- {reason}" for reason in reasons] + [""]
    automatic, passed, manual = progress(checklist, results(code, website) or {})
    lines.append(
        f"Checklist: {passed} of the {automatic} items the kit checks by itself passed. "
        f"{manual} more need you: evidence, a skill or a decision (checklist/CHECKLIST.md)."
    )
    if not website.strip():
        lines.append("")
        lines.append("This project has no website scan, so only the code checks count.")
    return "\n".join(lines) + "\n", points


def main(argv: list[str]) -> int:
    checklist = Path(argv[0]).read_text(encoding="utf-8") if argv else ""
    text, points = report(os.environ.get("CODE", ""), os.environ.get("WEBSITE", ""), checklist)
    print(text)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as out:
            out.write(f"score={points}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
