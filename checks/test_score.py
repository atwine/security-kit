"""Tests for the security score and checklist progress (checks/score.py). No network.

    python -m unittest discover -s checks -p "test_*.py" -v
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import score

CODE = ("secrets", "risky_code", "pins", "node_libraries", "python_libraries", "access_rules")
SITE = ("site_headers", "site_policy")
CHECKLIST = (Path(__file__).resolve().parent.parent / "checklist" / "CHECKLIST.md").read_text(encoding="utf-8")


def results(checks, **changed):
    data = {check: "success" for check in checks}
    data.update(changed)
    return json.dumps(data)


class Score(unittest.TestCase):
    def test_everything_passing_scores_100(self):
        self.assertEqual(score.score(results(CODE), results(SITE))[0], 100)

    def test_a_serious_finding_caps_the_score_at_49(self):
        points, reasons = score.score(results(CODE, secrets="failure"), results(SITE))
        self.assertLessEqual(points, 49)
        self.assertTrue(any("Leaked secrets" in reason for reason in reasons), reasons)

    def test_a_minor_finding_costs_points_without_a_cap(self):
        points, reasons = score.score(results(CODE, risky_code="failure"), results(SITE))
        self.assertEqual(points, 88)  # 7 of 8 checks passed
        self.assertEqual(reasons, [])

    def test_a_check_that_did_not_run_caps_the_score(self):
        points, reasons = score.score(results(CODE, pins=""), results(SITE))
        self.assertLessEqual(points, 49)
        self.assertTrue(reasons)

    def test_without_a_website_scan_only_the_code_checks_count(self):
        self.assertEqual(score.score(results(CODE, pins="failure"), "")[0], 83)  # 5 of 6

    def test_no_code_results_scores_0(self):
        points, reasons = score.score("", results(SITE))
        self.assertEqual(points, 0)
        self.assertTrue(reasons)

    def test_unreadable_results_score_0(self):
        self.assertEqual(score.score("not json", "")[0], 0)


class Progress(unittest.TestCase):
    def test_the_real_checklist_has_automatic_and_manual_items(self):
        automatic, passed, manual = score.progress(CHECKLIST, json.loads(results(CODE + SITE)))
        self.assertGreater(automatic, 5)
        self.assertEqual(passed, automatic)
        self.assertGreater(manual, 20)

    def test_an_item_passes_only_when_all_its_checks_pass(self):
        text = (
            "| SK-01 | a | AUTO `secrets` \u00b7 pre-commit | x |\n"
            "| SK-02 | b | AUTO `python_libraries`, `node_libraries` \u00b7 EVIDENCE y | x |\n"
            "| SK-03 | c | EVIDENCE review | x |\n"
            "| SK-04 | d | AUTO `site_headers` | x |\n"
        )
        automatic, passed, manual = score.progress(text, {"secrets": "success", "python_libraries": "success", "node_libraries": "failure"})
        self.assertEqual((automatic, passed, manual), (2, 1, 1))  # SK-04 isn't counted without a website scan


class Command(unittest.TestCase):
    def test_the_command_writes_the_summary_and_the_score_output(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "output"
            output.write_text("", encoding="utf-8")
            env = {"CODE": results(CODE, secrets="failure"), "WEBSITE": "", "GITHUB_OUTPUT": str(output)}
            with mock.patch.dict(os.environ, env), mock.patch("builtins.print") as printed:
                self.assertEqual(score.main([str(Path(__file__).resolve().parent.parent / "checklist" / "CHECKLIST.md")]), 0)
            text = " ".join(str(call.args[0]) for call in printed.call_args_list)
            self.assertIn("Security score", text)
            self.assertIn("score=", output.read_text(encoding="utf-8"))
            self.assertLessEqual(int(output.read_text(encoding="utf-8").split("score=")[1].strip()), 49)


if __name__ == "__main__":
    unittest.main()
