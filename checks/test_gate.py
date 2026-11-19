"""Tests for the code checks' pass/fail decision (checks/gate.py). No network.

    python -m unittest discover -s checks -p "test_*.py" -v

The decision must hold even when the checks jobs' record is incomplete:
GitHub drops a job output whose value contains text a step registered as a
secret (::add-mask::), so code that runs in a checks job can make a failing
check's result disappear.
"""

import contextlib
import io
import json
import os
import unittest
from unittest import mock

import gate

READ = ("secrets", "risky_code", "pins", "node_libraries")
RUN = ("python_libraries", "access_rules")


def needs(read=None, run=None, evidence=True):
    """The deciding job's needs: every check passed, with overrides."""

    def job(checks, changes):
        outputs = {check: "success" for check in checks}
        if evidence:
            outputs["evidence"] = "{}"
        for name, value in (changes or {}).items():
            if value is None:
                outputs.pop(name, None)
            else:
                outputs[name] = value
        return {"result": "success", "outputs": outputs}

    return {"read": job(READ, read), "run": job(RUN, run)}


class Decide(unittest.TestCase):
    def assert_fails(self, data, *words):
        problems, _ = gate.decide(data)
        self.assertTrue(problems, "the gate passed a run it must fail")
        for word in words:
            self.assertIn(word, " ".join(problems))

    def test_every_check_passing_passes(self):
        self.assertEqual(gate.decide(needs())[0], [])

    def test_a_check_that_found_something_fails(self):
        self.assert_fails(needs(read={"secrets": "failure"}), "secrets")

    def test_a_result_hidden_by_a_mask_fails(self):
        # ::add-mask::failure makes GitHub drop every output equal to "failure".
        self.assert_fails(needs(read={"secrets": None}), "secrets")

    def test_every_result_missing_fails(self):
        self.assert_fails({"read": {"result": "success", "outputs": {}}, "run": {"result": "success", "outputs": {}}})

    def test_a_missing_checks_job_fails(self):
        data = needs()
        del data["run"]
        self.assert_fails(data, "run")

    def test_an_unknown_result_fails(self):
        self.assert_fails(needs(read={"extra_check": "success"}), "extra_check")

    def test_a_skipped_check_fails(self):
        self.assert_fails(needs(run={"access_rules": "skipped"}), "access_rules")

    def test_a_checks_job_that_did_not_succeed_fails(self):
        data = needs()
        data["read"]["result"] = "failure"
        self.assert_fails(data, "read")

    def test_evidence_is_never_judged(self):
        self.assertEqual(gate.decide(needs(read={"evidence": "anything at all"}))[0], [])


class Main(unittest.TestCase):
    def run_main(self, data, **env):
        values = {"NEEDS": json.dumps(data), "ASKED_REPORT_ONLY": "false", "REPO": "someone/project", "KIT_REPO": "atwine/security-kit"}
        values.update(env)
        out = io.StringIO()
        with mock.patch.dict(os.environ, values, clear=True), contextlib.redirect_stdout(out):
            return gate.main(), out.getvalue()

    def test_a_project_fails_when_a_check_fails(self):
        code, _ = self.run_main(needs(read={"pins": "failure"}))
        self.assertEqual(code, 1)

    def test_a_project_cannot_switch_to_report_only(self):
        code, text = self.run_main(needs(read={"pins": "failure"}), ASKED_REPORT_ONLY="true")
        self.assertEqual(code, 1)
        self.assertIn("::warning::", text)

    def test_the_kit_itself_can_report_only(self):
        code, text = self.run_main(needs(read={"pins": "failure"}), ASKED_REPORT_ONLY="true", REPO="atwine/security-kit")
        self.assertEqual(code, 0)
        self.assertIn("::notice::", text)


if __name__ == "__main__":
    unittest.main()
