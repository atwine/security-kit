"""Read the reports the kit's checks write, and say what each one found.

    python findings.py evidence-code <reports folder>   # one line of JSON: check -> findings
    python findings.py evidence-site <ZAP folder>       # the same for the website scan
    python findings.py show npm|pip-audit <report>      # a short list for people

The evidence commands run only when the kit tests itself: the self-test
uses them to prove each check caught the defect it planted, not something
else. The show command prints npm audit's and pip-audit's findings for
everyone, because those tools write JSON instead of a table.

A missing report means nothing was found. A report that can't be read is
listed as "unreadable report: <name>", so it never counts as a clean result.
Standard library only.
"""

import html
import json
import re
import sys
from pathlib import Path

FAILING_NPM_SEVERITIES = ("high", "critical")  # matches npm audit --audit-level=high


def _load(path: Path):
    """The parsed JSON report, None when it doesn't exist, or a marker string when it can't be read."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return f"unreadable report: {path.name}"


def _read(path: Path, extract) -> list[str]:
    data = _load(path)
    if data is None:
        return []
    if isinstance(data, str):
        return [data]
    try:
        return extract(data)
    except (AttributeError, KeyError, TypeError, ValueError):
        return [f"unreadable report: {path.name}"]


def gitleaks(path: Path) -> list[str]:
    return _read(path, lambda data: [f"{leak['File']}:{leak.get('StartLine', '?')} ({leak['RuleID']})" for leak in data])


def semgrep(path: Path) -> list[str]:
    return _read(
        path,
        lambda data: [f"{hit['path']}:{hit.get('start', {}).get('line', '?')} ({hit['check_id']})" for hit in data["results"]],
    )


def pins(path: Path) -> list[str]:
    return _read(path, lambda data: [str(finding) for finding in data])


def npm(path: Path) -> list[str]:
    def extract(data):
        if "error" in data:
            return []
        return [
            f"{name} ({entry['severity']}, {entry.get('range', '?')})"
            for name, entry in sorted(data.get("vulnerabilities", {}).items())
            if entry["severity"] in FAILING_NPM_SEVERITIES
        ]

    return _read(path, extract)


def pip_audit(path: Path) -> list[str]:
    return _read(
        path,
        lambda data: [
            f"{dep['name']}=={dep['version']}: {', '.join(vuln['id'] for vuln in dep['vulns'])}"
            for dep in data["dependencies"]
            if dep.get("vulns")
        ],
    )


# pytest's JUnit XML is read with a pattern rather than an XML parser: the
# kit needs only each failing test's name and message, and this way no XML
# feature (entities, external references) is ever processed.
_TESTCASE = re.compile(r"<testcase\b([^>]*?)(?:/>|>(.*?)</testcase>)", re.S)
_PROBLEM = re.compile(r"<(failure|error)\b([^>]*)>", re.S)
_ATTRIBUTE = re.compile(r'([\w:-]+)="([^"]*)"')


def junit(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [f"unreadable report: {path.name}"]
    found = []
    for head, body in _TESTCASE.findall(text):
        problem = _PROBLEM.search(body or "")
        if not problem:
            continue
        case = {key: html.unescape(value) for key, value in _ATTRIBUTE.findall(head)}
        detail = {key: html.unescape(value) for key, value in _ATTRIBUTE.findall(problem.group(2))}
        lines = detail.get("message", "").strip().splitlines()
        message = lines[0] if lines else problem.group(1)
        found.append(f"{case.get('classname', '?')}.{case.get('name', '?')}: {message}")
    return found


def _failing_rules(rules: Path) -> set[str]:
    failing = set()
    for line in rules.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].startswith("#") and parts[1] == "FAIL":
            failing.add(parts[0])
    return failing


def zap(report: Path, rules: Path) -> list[str]:
    try:
        failing = _failing_rules(rules)
    except (OSError, UnicodeDecodeError):
        return [f"unreadable report: {rules.name}"]
    return _read(
        report,
        lambda data: sorted(
            {
                f"{alert['pluginid']} {alert.get('name', '?')}"
                for site in data.get("site", [])
                for alert in site.get("alerts", [])
                if str(alert.get("pluginid")) in failing
            }
        ),
    )


def code_evidence(folder: Path) -> dict[str, list[str]]:
    return {
        "secrets": gitleaks(folder / "gitleaks.json"),
        "risky_code": semgrep(folder / "semgrep.json"),
        "pins": pins(folder / "pins.json"),
        "node_libraries": npm(folder / "npm-audit.json"),
        "python_libraries": [item for report in sorted(folder.glob("pip-audit-*.json")) for item in pip_audit(report)],
        "access_rules": junit(folder / "access-tests.xml"),
    }


def site_evidence(folder: Path) -> dict[str, list[str]]:
    return {"site_headers": zap(folder / "report.json", folder / "rules.conf")}


def show(tool: str, report: Path) -> None:
    if tool == "npm":
        data = _load(report)
        if isinstance(data, dict) and "error" in data:
            error = data["error"]
            print(f"npm audit couldn't check: {error.get('summary') if isinstance(error, dict) else error}")
            return
        items, what = npm(report), "high or critical holes"
    elif tool == "pip-audit":
        if not report.is_file():
            print("pip-audit wrote no report, so it stopped before checking. Its messages are above.")
            return
        items, what = pip_audit(report), "known holes"
    else:
        raise SystemExit(f"unknown tool {tool!r}")
    unreadable = [item for item in items if item.startswith("unreadable report")]
    if unreadable:
        print(f"{tool}: {unreadable[0]}")
        return
    if not items:
        print(f"Nothing with {what}.")
        return
    print(f"{len(items)} with {what}:")
    for item in items:
        print(f"  {item}")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "evidence-code":
        print(json.dumps(code_evidence(Path(argv[1]))))
    elif len(argv) == 2 and argv[0] == "evidence-site":
        print(json.dumps(site_evidence(Path(argv[1]))))
    elif len(argv) == 3 and argv[0] == "show":
        show(argv[1], Path(argv[2]))
    else:
        print("\n".join(__doc__.strip().splitlines()[2:5]), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
