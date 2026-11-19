"""Tests for the report readers (checks/findings.py). No network, no tools.

    python -m unittest discover -s checks -p "test_*.py" -v

Each sample has the shape the pinned tool writes.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import findings

GITLEAKS = [
    {
        "RuleID": "github-pat",
        "Description": "Uncovered a GitHub Personal Access Token.",
        "StartLine": 1,
        "Match": "REDACTED",
        "Secret": "REDACTED",
        "File": "selftest/fixture-app/settings_local.py",
        "Commit": "0123456789abcdef0123456789abcdef01234567",
    }
]
SEMGREP = {
    "version": "1.186.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected.eval-detected",
            "path": "selftest/fixture-app/run_command.py",
            "start": {"line": 9, "col": 12},
            "end": {"line": 9, "col": 28},
            "extra": {"severity": "WARNING"},
        }
    ],
    "errors": [],
}
PINS = ["selftest/fixture-app/requirements.txt:1: `fastapi>=0.165.0` isn't pinned to one exact version (use ==)"]
NPM = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "high",
            "range": "<=4.17.23",
            "via": [
                {"source": 1094500, "title": "Command Injection in lodash", "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm", "severity": "high"},
                {"source": 1094499, "title": "Prototype Pollution in lodash", "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw", "severity": "high"},
            ],
        },
        "minimist": {
            "name": "minimist",
            "severity": "moderate",
            "range": "<1.2.6",
            "via": [{"source": 1096465, "title": "Prototype Pollution in minimist", "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h"}],
        },
        "wrapper": {"name": "wrapper", "severity": "high", "range": "1.0.0", "via": ["lodash"]},
    },
    "metadata": {"vulnerabilities": {"high": 2, "moderate": 1, "total": 3}},
}
NPM_ERROR = {"error": {"code": "ENOLOCK", "summary": "This command requires an existing lockfile.", "detail": ""}}
PIP_AUDIT = {
    "dependencies": [
        {"name": "fastapi", "version": "0.165.0", "vulns": []},
        {
            "name": "urllib3",
            "version": "1.26.4",
            "vulns": [
                {"id": "PYSEC-2021-108", "fix_versions": ["1.26.5"], "aliases": ["CVE-2021-33503"]},
                {"id": "PYSEC-2021-108", "fix_versions": ["1.26.5"], "aliases": ["CVE-2021-33503"]},
                {"id": "GHSA-v845-jxx5-vc9f", "fix_versions": ["1.26.17"], "aliases": ["CVE-2023-43804"]},
                {"id": "PYSEC-2026-0001", "fix_versions": [], "aliases": []},
            ],
        },
        {"name": "private-package", "skip_reason": "Dependency not found on PyPI"},
    ],
    "fixes": [],
}
JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites name="pytest tests"><testsuite name="pytest" errors="0" failures="1" skipped="0" tests="2">
<testcase classname="tests.test_access" name="test_every_route_has_an_access_rule" time="0.01">
<failure message="AssertionError: assert [('GET', '/admin/export')] == []&#10;  Left contains one more item">trace</failure>
</testcase>
<testcase classname="tests.test_access" name="test_something_else" time="0.01"/>
</testsuite></testsuites>
"""
ZAP_REPORT = {
    "@programName": "ZAP",
    "site": [
        {
            "@name": "http://127.0.0.1:8000",
            "alerts": [
                {"pluginid": "10038", "name": "Content Security Policy (CSP) Header Not Set", "riskdesc": "Medium (High)", "count": "3"},
                {"pluginid": "10063", "name": "Permissions Policy Header Not Set", "riskdesc": "Low (Medium)", "count": "3"},
                {"pluginid": "10020", "name": "Missing Anti-clickjacking Header", "riskdesc": "Medium (Medium)", "count": "1"},
            ],
        }
    ],
}
ZAP_RULES = "# comment\n10038\tFAIL\t(Content Security Policy (CSP) Header Not Set)\n10020\tFAIL\t(Missing Anti-clickjacking Header)\n10063\tWARN\t(Permissions Policy Header Not Set)\n"


class Readers(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def write(self, name, data):
        path = self.folder / name
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def test_gitleaks_names_the_file_and_rule(self):
        self.assertEqual(findings.gitleaks(self.write("gitleaks.json", GITLEAKS)), ["selftest/fixture-app/settings_local.py:1 (github-pat)"])

    def test_semgrep_names_the_file_line_and_rule(self):
        self.assertEqual(
            findings.semgrep(self.write("semgrep.json", SEMGREP)),
            ["selftest/fixture-app/run_command.py:9 (python.lang.security.audit.eval-detected.eval-detected)"],
        )

    def test_pins_returns_its_own_findings(self):
        self.assertEqual(findings.pins(self.write("pins.json", PINS)), PINS)

    def test_npm_names_each_failing_package_and_its_advisories(self):
        self.assertEqual(
            findings.npm(self.write("npm-audit.json", NPM)),
            ["lodash (high, <=4.17.23): GHSA-35jh-r3h4-6jhm, GHSA-p6mc-m468-83gw", "wrapper (high, 1.0.0): through lodash"],
        )

    def test_an_npm_error_is_not_a_finding(self):
        self.assertEqual(findings.npm(self.write("npm-audit.json", NPM_ERROR)), [])

    def test_pip_audit_names_each_vulnerable_package_and_its_advisories_once(self):
        self.assertEqual(
            findings.pip_audit(self.write("pip-audit-1.json", PIP_AUDIT)),
            ["urllib3==1.26.4: PYSEC-2021-108, GHSA-v845-jxx5-vc9f, PYSEC-2026-0001"],
        )

    def test_junit_names_each_failing_test_and_its_first_message_line(self):
        self.assertEqual(
            findings.junit(self.write("access-tests.xml", JUNIT)),
            ["tests.test_access.test_every_route_has_an_access_rule: AssertionError: assert [('GET', '/admin/export')] == []"],
        )

    def test_zap_keeps_only_alerts_whose_rule_fails_the_scan(self):
        self.assertEqual(
            findings.zap(self.write("report.json", ZAP_REPORT), self.write("rules.conf", ZAP_RULES)),
            ["10020 Missing Anti-clickjacking Header", "10038 Content Security Policy (CSP) Header Not Set"],
        )

    def test_a_missing_report_has_no_findings(self):
        self.assertEqual(findings.gitleaks(self.folder / "absent.json"), [])

    def test_an_unreadable_report_says_so(self):
        self.assertEqual(findings.semgrep(self.write("semgrep.json", "{not json")), ["unreadable report: semgrep.json"])

    def test_code_evidence_covers_every_check(self):
        self.write("gitleaks.json", GITLEAKS)
        self.write("pip-audit-1.json", PIP_AUDIT)
        self.write("pip-audit-2.json", {"dependencies": [], "fixes": []})
        evidence = findings.code_evidence(self.folder)
        self.assertEqual(sorted(evidence), sorted(["secrets", "risky_code", "pins", "node_libraries", "python_libraries", "access_rules"]))
        self.assertEqual(evidence["secrets"], ["selftest/fixture-app/settings_local.py:1 (github-pat)"])
        self.assertEqual(evidence["python_libraries"], ["urllib3==1.26.4: PYSEC-2021-108, GHSA-v845-jxx5-vc9f, PYSEC-2026-0001"])
        self.assertEqual(evidence["risky_code"], [])

    def test_site_evidence_reads_the_scan_folder(self):
        self.write("report.json", ZAP_REPORT)
        self.write("rules.conf", ZAP_RULES)
        self.assertEqual(
            findings.site_evidence(self.folder),
            {"site_headers": ["10020 Missing Anti-clickjacking Header", "10038 Content Security Policy (CSP) Header Not Set"]},
        )

    def test_the_evidence_command_prints_one_line_of_json(self):
        self.write("gitleaks.json", GITLEAKS)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(findings.main(["evidence-code", str(self.folder)]), 0)
        self.assertEqual(len(out.getvalue().strip().splitlines()), 1)
        self.assertEqual(json.loads(out.getvalue())["secrets"], ["selftest/fixture-app/settings_local.py:1 (github-pat)"])

    def show(self, tool, report):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(findings.main(["show", tool, str(report)]), 0)
        return out.getvalue()

    def test_show_lists_npm_advisories_with_links_for_people(self):
        text = self.show("npm", self.write("npm-audit.json", NPM))
        self.assertIn("3 packages with known holes (2 high or critical, which fail this check)", text)
        self.assertIn("Command Injection in lodash: https://github.com/advisories/GHSA-35jh-r3h4-6jhm", text)
        self.assertIn("minimist (moderate, <1.2.6)", text)
        self.assertIn("through lodash", text)

    def test_show_lists_pip_audit_advisories_once_with_fixed_versions(self):
        text = self.show("pip-audit", self.write("pip-audit-1.json", PIP_AUDIT))
        self.assertIn("1 package with known holes", text)
        self.assertEqual(text.count("PYSEC-2021-108 (fixed in 1.26.5)"), 1)
        self.assertIn("PYSEC-2026-0001 (no fixed version yet)", text)

    def test_show_explains_an_npm_error(self):
        self.assertIn("This command requires an existing lockfile.", self.show("npm", self.write("npm-audit.json", NPM_ERROR)))

    def test_show_explains_a_missing_pip_audit_report(self):
        self.assertIn("wrote no report", self.show("pip-audit", self.folder / "pip-audit-9.json"))

    def test_show_says_when_a_report_is_unreadable(self):
        self.assertIn("unreadable report", self.show("pip-audit", self.write("pip-audit-1.json", {"dependencies": "oops"})))


if __name__ == "__main__":
    unittest.main()
