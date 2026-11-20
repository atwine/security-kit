"""Group I: the kit's docs say only what its checks do, and the release is tidy. No network.

    python -m unittest discover -s checks -p "test_*.py" -v
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


def read(*parts: str) -> str:
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


def checklist_row(item: str) -> str:
    return next(line for line in read("checklist", "CHECKLIST.md").splitlines() if line.startswith(f"| {item} "))


def run_lines(name: str) -> list[str]:
    """Shell lines of a workflow's run: blocks, as the runner would see them."""
    lines, inside, indent = [], False, 0
    for line in read(".github", "workflows", name).splitlines():
        stripped = line.lstrip()
        if inside and stripped and len(line) - len(stripped) <= indent:
            inside = False
        if inside:
            lines.append(stripped)
        match = re.match(r"(\s*)(- )?run: (.*)$", line)
        if match:
            indent = len(match.group(1))
            if match.group(3).strip() in ("|", ">"):
                inside = True
            else:
                lines.append(match.group(3).strip())
    return lines


class ReleasePrep(unittest.TestCase):
    def test_the_phase_1_test_workflow_is_gone(self):
        self.assertFalse((WORKFLOWS / "spike-hello.yml").exists())
        self.assertNotIn("Not ready for general use", read("README.md"))

    def test_sk_52_names_the_release_gate_that_exists(self):
        self.assertNotIn("planned", checklist_row("SK-52"))

    def test_sk_02_says_which_holes_npm_audit_fails_on(self):
        row = checklist_row("SK-02")
        self.assertIn("high", row)
        self.assertIn("development", row)

    def test_sk_11_does_not_promise_the_kit_finds_routes_without_rules(self):
        self.assertNotIn("a new route without a rule fails the build", checklist_row("SK-11"))

    def test_the_kit_has_its_own_security_policy(self):
        text = read("SECURITY.md")
        self.assertIn("security/advisories/new", text)
        self.assertNotIn("CONTACT ADDRESS", text)

    def test_releasing_says_how_to_review_a_drafted_kit_change(self):
        text = read("RELEASING.md")
        self.assertIn("security review", text)
        self.assertIn("source link", text)

    def test_gitleaks_prints_the_file_and_line_of_a_leak(self):
        line = next(line for line in run_lines("scans.yml") if line.startswith("gitleaks git"))
        self.assertIn(" -v", line)

    def test_downloads_are_https_only_and_arguments_cannot_be_options(self):
        for name in ("scans.yml", "site-scan.yml"):
            for line in run_lines(name):
                words = line.split()
                if "curl" in words[:2]:
                    self.assertIn("--proto =https", line, f"{name}: {line}")
                for tool in ("curl", "cp"):
                    if tool in words[:2]:
                        self.assertIn(" -- ", line, f"{name}: {line}")

    def test_the_watcher_tracks_only_the_stacks_the_owner_chose(self):
        words = json.loads(read("watch", "sources.json"))["exploited"]["words"]
        self.assertNotIn("vercel", words)

    def test_the_watcher_does_not_claim_every_audit_sees_the_library(self):
        self.assertNotIn("audits already flag the library itself", read("watch", "watch.py"))

    def test_the_nextjs_guide_does_not_steer_projects_to_switch_off_the_csp_check(self):
        text = read("templates", "headers", "nextjs.md")
        self.assertIn("10038", text)
        self.assertIn("IGNORE", text)

    def test_the_llm_list_is_named_as_the_checklist_names_it(self):
        label = json.loads(read("watch", "sources.json"))["owasp"]["llm_top10"]["label"]
        self.assertIn("2025", label)


if __name__ == "__main__":
    unittest.main()
