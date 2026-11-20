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
        row = checklist_row("SK-52")
        self.assertNotIn("planned", row)
        self.assertIn("outside the kit", row)
        self.assertIn("opened by hand isn't stopped", row)

    def test_sk_02_says_which_holes_npm_audit_fails_on(self):
        row = checklist_row("SK-02")
        self.assertIn("high or critical holes in JavaScript libraries", row)
        self.assertIn("not development-only", row)

    def test_sk_11_does_not_promise_the_kit_finds_routes_without_rules(self):
        row = checklist_row("SK-11")
        self.assertNotIn("a new route without a rule fails the build", row)
        self.assertIn("up to the tests", row)
        self.assertIn("no `ACCESS.md`", row)

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
        # The website scan's curl only asks the project's own app, often plain
        # http://localhost, whether it answers; it may use http but nothing else.
        allowed = {"scans.yml": "--proto =https ", "site-scan.yml": "--proto =http,https "}
        for name in ("scans.yml", "site-scan.yml"):
            for line in run_lines(name):
                words = line.split()
                if "curl" in words[:2]:
                    self.assertIn(allowed[name], line, f"{name}: {line}")
                for tool in ("curl", "cp"):
                    # Every call on the line, including one after "then" or "else".
                    for index, word in enumerate(words):
                        if word == tool:
                            self.assertIn("--", words[index + 1:], f"{name}: {line}")

    def test_the_watcher_tracks_only_the_stacks_the_owner_chose(self):
        words = json.loads(read("watch", "sources.json"))["exploited"]["words"]
        self.assertNotIn("vercel", words)

    def test_the_watcher_does_not_claim_every_audit_sees_the_library(self):
        text = read("watch", "watch.py")
        self.assertNotIn("audits already flag the library itself", text)
        self.assertIn("not when a framework bundles a copy", text)

    def test_the_nextjs_guide_does_not_steer_projects_to_switch_off_the_csp_check(self):
        text = " ".join(read("templates", "headers", "nextjs.md").split())
        self.assertIn("Don't add a `10038 IGNORE` or `10038 WARN` line", text)

    def test_the_llm_list_is_named_as_the_checklist_names_it(self):
        # The checklist cites the 2025 list; OWASP's GitHub tags it 2024. The
        # label says so without naming a year that goes stale.
        label = json.loads(read("watch", "sources.json"))["owasp"]["llm_top10"]["label"]
        self.assertIn("release tag", label)
        self.assertNotRegex(label, r"\d{4}")


class EasySetup(unittest.TestCase):
    """Step 4 of the reporting plan: setting up a project starts with asking Claude."""

    def setup_section(self):
        text = read("README.md")
        return text.split("## Using it in a project", 1)[1].split("\n## ", 1)[0]

    def test_the_first_step_is_asking_claude(self):
        first = self.setup_section().split("\n2.", 1)[0]
        self.assertIn("set up the security kit", first)
        self.assertIn("secure-start", first)

    def test_it_says_how_results_come_back(self):
        section = self.setup_section()
        self.assertIn("score", section)
        self.assertIn("security-report", section)


if __name__ == "__main__":
    unittest.main()
