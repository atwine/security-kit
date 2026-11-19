"""Tests for the self-test's verdict (selftest/verdict.py). No network, no GitHub.

    python -m unittest discover -s selftest -p "test_*.py" -v

Each test starts from a run where everything went right, breaks one thing,
and checks the verdict notices.
"""

import copy
import json
import unittest

import verdict


def scan_job(checks, failing=None, found=()):
    results = {check: "success" for check in checks}
    evidence = {check: [] for check in checks}
    if failing:
        results[failing] = "failure"
        evidence[failing] = list(found)
    return {"result": "success", "outputs": {"results": json.dumps(results), "evidence": json.dumps(evidence)}}


def good_run():
    """The needs of a self-test run where every job did what it must."""
    needs = {"clean": scan_job(verdict.CODE_CHECKS), "site-clean": scan_job(verdict.SITE_CHECKS)}
    for job, check, planted in verdict.EXPECTED.values():
        checks = verdict.SITE_CHECKS if check in verdict.SITE_CHECKS else verdict.CODE_CHECKS
        needs[job] = scan_job(checks, check, [f"a report line naming {item}" for item in planted])
    for job in verdict.UNIT_TESTS:
        needs[job] = {"result": "success", "outputs": {}}
    return needs


def edit(needs, job, key, change):
    outputs = needs[job]["outputs"]
    data = json.loads(outputs[key])
    change(data)
    outputs[key] = json.dumps(data)


def set_result(needs, job, check, outcome):
    edit(needs, job, "results", lambda results: results.__setitem__(check, outcome))


def drop_result(needs, job, check):
    edit(needs, job, "results", lambda results: results.pop(check))


def set_evidence(needs, job, check, items):
    edit(needs, job, "evidence", lambda evidence: evidence.__setitem__(check, items))


class Verdict(unittest.TestCase):
    def assert_fails(self, needs, *words):
        problems, _ = verdict.decide(needs)
        self.assertTrue(problems, "the verdict passed a run it must fail")
        text = " ".join(problems)
        for word in words:
            self.assertIn(word, text)

    def test_a_run_where_everything_went_right_passes(self):
        problems, lines = verdict.decide(good_run())
        self.assertEqual(problems, [])
        self.assertIn(f"Caught {len(verdict.EXPECTED)} of {len(verdict.EXPECTED)}.", lines)

    def test_a_missing_result_fails(self):
        needs = good_run()
        drop_result(needs, "unpinned-library", "pins")
        self.assert_fails(needs, "unpinned-library")

    def test_a_missing_job_fails(self):
        needs = good_run()
        del needs["risky-code"]
        self.assert_fails(needs, "risky-code")

    def test_a_clean_run_missing_a_check_fails(self):
        needs = good_run()
        drop_result(needs, "clean", "node_libraries")
        self.assert_fails(needs, "node_libraries")

    def test_a_failure_whose_report_does_not_name_the_planted_item_fails(self):
        needs = good_run()
        set_evidence(needs, "vulnerable-library", "python_libraries", [])
        self.assert_fails(needs, "vulnerable-library")

    def test_naming_only_some_of_the_planted_items_fails(self):
        needs = good_run()
        set_evidence(needs, "site-missing-headers", "site_headers", ["10038 Content Security Policy (CSP) Header Not Set"])
        self.assert_fails(needs, "missing-headers")

    def test_a_newer_fastapi_in_the_fixture_still_counts(self):
        # Dependabot updates the fixture's libraries, so the planted loose pin
        # can carry any fastapi version.
        needs = good_run()
        line = "selftest/fixture-app/requirements.txt:1: `fastapi>=0.170.2` isn't pinned to one exact version (use ==)"
        set_evidence(needs, "unpinned-library", "pins", [line])
        self.assertEqual(verdict.decide(needs)[0], [])

    def test_a_similar_package_name_does_not_count(self):
        needs = good_run()
        set_evidence(needs, "node-library", "node_libraries", ["lodash-es (high, <=4.17.21): GHSA-aaaa-bbbb-cccc"])
        self.assert_fails(needs, "node-library")

    def test_another_check_failing_in_a_defect_run_fails(self):
        needs = good_run()
        set_result(needs, "vulnerable-library", "access_rules", "failure")
        self.assert_fails(needs, "vulnerable-library", "access_rules")

    def test_another_check_reporting_something_in_a_defect_run_fails(self):
        needs = good_run()
        set_evidence(needs, "secret", "risky_code", ["selftest/fixture-app/settings_local.py:1 (some-rule)"])
        self.assert_fails(needs, "secret", "risky_code")

    def test_the_clean_app_with_something_reported_fails(self):
        needs = good_run()
        set_evidence(needs, "clean", "secrets", ["selftest/fixture-app/app.py:3 (generic-api-key)"])
        self.assert_fails(needs, "clean", "secrets")

    def test_a_job_that_did_not_succeed_fails(self):
        needs = good_run()
        needs["hidden-folder-code"]["result"] = "failure"
        self.assert_fails(needs, "hidden-folder-code")

    def test_failing_unit_tests_fail(self):
        for job in verdict.UNIT_TESTS:
            needs = good_run()
            needs[job]["result"] = "failure"
            self.assert_fails(needs, job)

    def test_a_job_the_verdict_does_not_know_fails(self):
        needs = good_run()
        needs["new-defect"] = copy.deepcopy(needs["secret"])
        self.assert_fails(needs, "new-defect")

    def test_evidence_from_two_checks_jobs_is_read_together(self):
        needs = good_run()
        outputs = needs["secret"]["outputs"]
        evidence = json.loads(outputs.pop("evidence"))
        outputs["evidence-read"] = json.dumps({k: v for k, v in evidence.items() if k != "access_rules"})
        outputs["evidence-run"] = json.dumps({"access_rules": evidence["access_rules"]})
        self.assertEqual(verdict.decide(needs)[0], [])

    def test_unreadable_evidence_fails(self):
        needs = good_run()
        needs["secret"]["outputs"]["evidence"] = "not json"
        self.assert_fails(needs, "secret")

    def test_the_crash_in_run_44559506410_is_not_a_catch(self):
        # In self-test run 44559506410, pip stopped on a version conflict
        # before pip-audit looked anything up. python_libraries and
        # access_rules both failed, and no report named a vulnerable package.
        needs = good_run()
        set_result(needs, "vulnerable-library", "access_rules", "failure")
        set_evidence(needs, "vulnerable-library", "python_libraries", [])
        problems, lines = verdict.decide(needs)
        self.assertTrue(problems)
        self.assertFalse([line for line in lines if "vulnerable-library" in line and "CAUGHT" in line])


if __name__ == "__main__":
    unittest.main()
