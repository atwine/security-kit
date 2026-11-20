"""Read the reports the kit's checks write, and say what each one found.

    python findings.py evidence-code <reports folder> [check ...]   # one line of JSON: check -> findings
    python findings.py evidence-site <ZAP folder>       # the same for the website scan
    python findings.py show npm|pip-audit <report>      # a short list for people
    python findings.py summary <reports folder> check=outcome ...       # Markdown for the run's summary page
    python findings.py summary-site <ZAP folder> check=outcome ...      # the same for the website scan

The evidence commands run only in the kit's own repository. Its self-test
uses them to prove each check caught the defect it planted, not something
else. The show command prints npm audit's and pip-audit's findings, with
advisory links and fixed versions, for every project, because those tools
now write JSON instead of a table.

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


_ADVISORY_ID = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}")


def _npm_advisories(entry: dict) -> list[tuple[str, str, str]]:
    """(id, title, url) of each advisory npm lists for a package; string entries name other packages."""
    found = []
    for via in entry.get("via", []):
        if isinstance(via, dict):
            url = str(via.get("url", ""))
            match = _ADVISORY_ID.search(url)
            found.append((match.group(0) if match else str(via.get("source", "?")), str(via.get("title", "")), url))
    return found


def _unique(items) -> list:
    return list(dict.fromkeys(items))


def npm(path: Path) -> list[str]:
    def extract(data):
        if "error" in data:
            return []
        found = []
        for name, entry in sorted(data.get("vulnerabilities", {}).items()):
            if entry["severity"] in FAILING_NPM_SEVERITIES:
                ids = _unique(advisory_id for advisory_id, _, _ in _npm_advisories(entry))
                via = ", ".join(ids) or "through " + ", ".join(str(v) for v in entry.get("via", []))
                found.append(f"{name} ({entry['severity']}, {entry.get('range', '?')}): {via}")
        return found

    return _read(path, extract)


def pip_audit(path: Path) -> list[str]:
    return _read(
        path,
        lambda data: [
            f"{dep['name']}=={dep['version']}: {', '.join(_unique(vuln['id'] for vuln in dep['vulns']))}"
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


def _each(folder: Path, pattern: str, reader) -> list[str]:
    return [item for report in sorted(folder.glob(pattern)) for item in reader(report)]


CODE_READERS = {
    "secrets": lambda folder: gitleaks(folder / "gitleaks.json"),
    "risky_code": lambda folder: semgrep(folder / "semgrep.json"),
    "pins": lambda folder: pins(folder / "pins.json"),
    "node_libraries": lambda folder: _each(folder, "npm-audit*.json", npm),
    "python_libraries": lambda folder: _each(folder, "pip-audit-*.json", pip_audit),
    "access_rules": lambda folder: _each(folder, "access-tests*.xml", junit),
}


def _not_checked(folder: Path) -> dict:
    data = _load(folder / "not-checked.json")
    return data if isinstance(data, dict) else {}


def code_evidence(folder: Path, checks=None) -> dict[str, list[str]]:
    """What each code check's report named, plus what it couldn't look at; checks limits it to one job's checks."""
    skipped = _not_checked(folder)
    return {check: CODE_READERS[check](folder) + [f"not checked: {path}" for path in skipped.get(check, [])] for check in (checks or CODE_READERS)}


def site_policy(path: Path) -> list[str]:
    """The kit website check's findings that weren't accepted."""
    return _read(path, lambda data: [str(item) for item in data["failing"]])


def site_evidence(folder: Path) -> dict[str, list[str]]:
    return {
        "site_headers": zap(folder / "report.json", folder / "rules.conf"),
        "site_policy": site_policy(folder / "site-policy.json"),
    }


# What each check is called on the summary page, and what to do when it finds something.
CHECK_TEXT = {
    "secrets": ("Leaked secrets (gitleaks)",
                "remove the secret from the code, then make a new one and stop using the old one: it stays in the git history."),
    "risky_code": ("Risky code patterns (Semgrep)",
                   "open each line and fix the pattern. If it is safe, add a `nosemgrep` comment saying why."),
    "pins": ("Pinned versions",
             "pin each item to one exact version: `==` for a library, a full commit for an action, a digest for an image."),
    "node_libraries": ("JavaScript libraries (npm audit)",
                       "update each package to a version with the fix (`npm audit fix`, or raise it in package.json)."),
    "python_libraries": ("Python libraries (pip-audit)",
                         "update each library to a version with the fix, in requirements.txt or pyproject.toml."),
    "access_rules": ("Access rules (the project's access tests)",
                     "fix the failing access tests or the route they caught. A route with no rule needs a test (the access-guard skill writes one)."),
    "site_headers": ("Website safety headers (ZAP)",
                     "add the missing headers; templates/headers in the kit has safe defaults."),
    "site_policy": ("Website rules (HTTPS, cookies, CORS)",
                    "fix each item: Strict-Transport-Security, Referrer-Policy, Permissions-Policy, cookie flags and CORS."),
}
NOT_CHECKED = "not checked: "
SHOWN = 20


def _cell(text: str) -> str:
    """Text from a report, made safe for one Markdown table cell or list item."""
    return " ".join(str(text).split()).replace("`", "'").replace("|", "/")


def _result(outcome: str, found: list[str], skipped: list[str]) -> str:
    if outcome == "success":
        return "passed"
    if outcome == "failure":
        parts = ([f"found {len(found)}"] if found else []) + ([f"couldn't check {len(skipped)}"] if skipped else [])
        return ", ".join(parts) or "failed"
    return f"didn't run ({outcome})" if outcome else "didn't run"


def summary(outcomes: dict[str, str], evidence: dict[str, list[str]]) -> str:
    """Markdown for the run's summary page: a table of every check, then what each one that isn't clean found."""
    table = ["| Check | Result |", "|---|---|"]
    details = []
    for check, outcome in outcomes.items():
        title, advice = CHECK_TEXT.get(check, (check, "see this check's step log."))
        items = evidence.get(check, [])
        found = [item for item in items if not item.startswith(NOT_CHECKED)]
        skipped = [item[len(NOT_CHECKED):] for item in items if item.startswith(NOT_CHECKED)]
        result = _result(outcome, found, skipped)
        table.append(f"| {title} | {result} |")
        if result == "passed":
            continue
        lines = [f"**{title}: {result}.**", ""]
        if found:
            lines.append(f"What to do: {advice}")
        if skipped:
            lines.append("Couldn't check these, so the check fails until they can be checked or are removed:")
        if not found and not skipped:
            lines.append("No details in its report. Open this check's step log.")
        lines.append("")
        shown = [f"- `{_cell(item)}`" for item in found + skipped]
        lines += shown[:SHOWN]
        if len(shown) > SHOWN:
            lines.append(f"- and {len(shown) - SHOWN} more (see the step log)")
        details.append("\n".join(lines))
    return "\n\n".join(["\n".join(table)] + details) + "\n"


def _outcomes(pairs: list[str]) -> dict[str, str]:
    return dict(pair.split("=", 1) for pair in pairs)


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _show_npm(data: dict) -> None:
    if "error" in data:
        error = data["error"]
        print(f"npm audit couldn't check: {error.get('summary') if isinstance(error, dict) else error}")
        return
    packages = sorted((data.get("vulnerabilities") or {}).items())
    if not packages:
        print("npm audit found no known holes.")
        return
    failing = sum(entry.get("severity") in FAILING_NPM_SEVERITIES for _, entry in packages)
    print(f"npm audit found {_plural(len(packages), 'package')} with known holes ({failing} high or critical, which fail this check):")
    for name, entry in packages:
        print(f"  {name} ({entry.get('severity', '?')}, {entry.get('range', '?')})")
        advisories = _npm_advisories(entry)
        for advisory_id, title, url in advisories:
            print(f"    {title or advisory_id}: {url or advisory_id}")
        if not advisories:
            print(f"    through {', '.join(str(v) for v in entry.get('via', []))}")


def _show_pip_audit(data: dict) -> None:
    vulnerable = [dep for dep in data["dependencies"] if dep.get("vulns")]
    if not vulnerable:
        print("pip-audit found no known holes.")
        return
    print(f"pip-audit found {_plural(len(vulnerable), 'package')} with known holes:")
    for dep in vulnerable:
        print(f"  {dep['name']} {dep['version']}")
        for vuln_id in _unique(vuln["id"] for vuln in dep["vulns"]):
            fixes = _unique(v for vuln in dep["vulns"] if vuln["id"] == vuln_id for v in vuln.get("fix_versions") or [])
            print(f"    {vuln_id} ({'fixed in ' + ', '.join(fixes) if fixes else 'no fixed version yet'})")


def show(tool: str, report: Path) -> None:
    """Print what npm audit or pip-audit reported, for people reading the log."""
    if tool not in ("npm", "pip-audit"):
        raise SystemExit(f"unknown tool {tool!r}")
    name = "npm audit" if tool == "npm" else "pip-audit"
    data = _load(report)
    if data is None:
        print(f"{name} wrote no report, so it stopped before checking. Its messages are above.")
        return
    if isinstance(data, str):
        print(f"{name}: {data}")
        return
    try:
        (_show_npm if tool == "npm" else _show_pip_audit)(data)
    except (AttributeError, KeyError, TypeError, ValueError):
        print(f"{name}: unreadable report: {report.name}")


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "evidence-code" and set(argv[2:]) <= set(CODE_READERS):
        evidence = code_evidence(Path(argv[1]), argv[2:])
        report = _load(Path(argv[1]) / "semgrep.json")
        if isinstance(report, dict) and report.get("version"):
            evidence["_versions"] = {"semgrep": str(report["version"])}
        print(json.dumps(evidence))
    elif len(argv) == 2 and argv[0] == "evidence-site":
        evidence = site_evidence(Path(argv[1]))
        report = _load(Path(argv[1]) / "report.json")
        if isinstance(report, dict) and report.get("@version"):
            evidence["_versions"] = {"zap": str(report["@version"])}
        print(json.dumps(evidence))
    elif len(argv) >= 3 and argv[0] in ("summary", "summary-site") and all("=" in pair for pair in argv[2:]):
        outcomes = _outcomes(argv[2:])
        folder = Path(argv[1])
        if argv[0] == "summary":
            evidence = code_evidence(folder, [check for check in outcomes if check in CODE_READERS])
        else:
            evidence = site_evidence(folder)
        print(summary(outcomes, evidence))
    elif len(argv) == 3 and argv[0] == "show":
        show(argv[1], Path(argv[2]))
    else:
        print("\n".join(__doc__.strip().splitlines()[2:7]), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
