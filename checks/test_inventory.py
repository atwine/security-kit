"""Tests for the inventory of what each check must cover (checks/inventory.py). No network.

    python -m unittest discover -s checks -p "test_*.py" -v

Each test gives the inventory a list of tracked files, as `git ls-files`
would, and checks what it hands to the checks and what it reports as not
checked.
"""

import unittest

import inventory


class Node(unittest.TestCase):
    def test_every_npm_lockfile_is_audited_where_it_lives(self):
        files = ["package.json", "package-lock.json", "frontend/package.json", "frontend/package-lock.json", "tools/npm-shrinkwrap.json"]
        self.assertEqual(inventory.node(files)["audit"], [".", "frontend", "tools"])

    def test_lockfiles_npm_cannot_read_are_not_checked(self):
        files = ["web/package.json", "web/yarn.lock", "app/pnpm-lock.yaml", "edge/bun.lockb"]
        self.assertEqual(inventory.node(files)["not_checked"], ["app/pnpm-lock.yaml", "edge/bun.lockb", "web/yarn.lock"])

    def test_a_lockfile_next_to_an_npm_lockfile_is_still_not_checked(self):
        # npm audit reads only the npm lockfile; the yarn one may hold other versions.
        files = ["web/package.json", "web/package-lock.json", "web/yarn.lock"]
        self.assertEqual(inventory.node(files), {"audit": ["web"], "not_checked": ["web/yarn.lock"]})

    def test_a_package_json_without_any_lockfile_is_left_to_the_pin_check(self):
        self.assertEqual(inventory.node(["package.json"]), {"audit": [], "not_checked": []})


PROJECT = '[project]\nname = "w"\nversion = "1"\ndependencies = ["urllib3==1.26.4"]\n'
TOOLS_ONLY = "[tool.ruff]\nline-length = 100\n"
POETRY = '[tool.poetry.dependencies]\npython = "^3.12"\nrequests = "2.0"\n'


class Python(unittest.TestCase):
    def test_requirements_files_and_pyproject_projects_are_audited(self):
        files = ["requirements.txt", "requirements/base.txt", "worker/pyproject.toml", "worker/app.py"]
        found = inventory.python(files, lambda path: PROJECT)
        self.assertEqual(found["requirements"], ["requirements.txt", "requirements/base.txt"])
        self.assertEqual(found["projects"], ["worker"])

    def test_a_pyproject_with_only_tool_settings_is_not_a_project(self):
        self.assertEqual(inventory.python(["pyproject.toml"], lambda path: TOOLS_ONLY), {"requirements": [], "projects": [], "not_checked": []})

    def test_a_pyproject_pip_audit_cannot_read_is_not_checked(self):
        self.assertEqual(inventory.python(["svc/pyproject.toml"], lambda path: POETRY)["not_checked"], ["svc/pyproject.toml"])

    def test_a_lockfile_with_nothing_pip_audit_reads_is_not_checked(self):
        self.assertEqual(inventory.python(["svc/poetry.lock", "svc/main.py"], lambda path: "")["not_checked"], ["svc/poetry.lock"])

    def test_locked_versions_without_an_exported_requirements_file_are_not_checked(self):
        # pip-audit resolves a pyproject afresh, so the locked versions that
        # deploy would go unaudited.
        self.assertEqual(inventory.python(["svc/pyproject.toml", "svc/uv.lock"], lambda path: PROJECT)["not_checked"], ["svc/uv.lock"])

    def test_a_lockfile_next_to_an_exported_requirements_file_is_covered(self):
        self.assertEqual(inventory.python(["svc/poetry.lock", "svc/requirements.txt"], lambda path: "")["not_checked"], [])

    def test_other_python_manifests_without_a_readable_one_are_not_checked(self):
        files = ["a/setup.py", "b/setup.cfg", "c/Pipfile", "d/requirements.in", "e/requirements.in", "e/requirements.txt"]
        self.assertEqual(inventory.python(files, lambda path: "")["not_checked"], ["a/setup.py", "b/setup.cfg", "c/Pipfile", "d/requirements.in"])

    def test_dependencies_filled_in_at_build_time_are_not_checked(self):
        dynamic = '[project]\nname = "w"\nversion = "1"\ndynamic = ["dependencies"]\n'
        self.assertEqual(inventory.python(["pyproject.toml"], lambda path: dynamic)["not_checked"], ["pyproject.toml"])

    def test_a_project_with_no_dependencies_has_nothing_to_audit(self):
        bare = '[project]\nname = "w"\nversion = "1"\n'
        self.assertEqual(inventory.python(["pyproject.toml"], lambda path: bare), {"requirements": [], "projects": [], "not_checked": []})

    def test_pip_audit_packages_it_could_not_look_up_are_not_checked(self):
        report = {"dependencies": [{"name": "w", "skip_reason": "not on PyPI"}, {"name": "private-lib", "skip_reason": "not on PyPI"}, {"name": "x", "version": "1", "vulns": []}]}
        self.assertEqual(inventory.pip_audit_skips(report, {"w"}), ["private-lib (not on PyPI)"])


class Access(unittest.TestCase):
    def test_access_tests_are_found_by_name_next_to_access_md(self):
        files = ["ACCESS.md", "tests/test_route_access.py", "tests/test_other.py", "app.py"]
        self.assertEqual(inventory.access(files, []), {"suites": [{"folder": ".", "tests": ["tests/test_route_access.py"]}], "not_checked": []})

    def test_each_access_md_is_tested_from_its_own_folder(self):
        files = ["selftest/fixture-app/ACCESS.md", "selftest/fixture-app/tests/test_access.py"]
        self.assertEqual(inventory.access(files, [])["suites"], [{"folder": "selftest/fixture-app", "tests": ["tests/test_access.py"]}])

    def test_access_md_without_access_tests_is_not_checked(self):
        self.assertEqual(inventory.access(["ACCESS.md", "tests/test_other.py"], [])["not_checked"], ["ACCESS.md"])

    def test_tests_elsewhere_in_the_working_folder_count(self):
        files = ["docs/ACCESS.md", "tests/test_access_rules.py"]
        self.assertEqual(inventory.access(files, [])["suites"], [{"folder": ".", "tests": ["tests/test_access_rules.py"]}])

    def test_a_root_access_md_counts_when_the_app_is_in_a_subfolder(self):
        files = ["ACCESS.md", "backend/requirements.txt", "backend/tests/test_access.py", "frontend/app.ts"]
        self.assertEqual(inventory.access(files, [], "backend"), {"suites": [{"folder": "backend", "tests": ["tests/test_access.py"]}], "not_checked": []})

    def test_a_root_access_md_with_no_tests_in_the_subfolder_is_not_checked(self):
        self.assertEqual(inventory.access(["ACCESS.md", "backend/app.py"], [], "backend")["not_checked"], ["ACCESS.md"])

    def test_tests_run_from_the_folder_holding_their_requirements(self):
        files = ["ACCESS.md", "backend/requirements.txt", "backend/tests/test_access.py"]
        self.assertEqual(inventory.access(files, [])["suites"], [{"folder": "backend", "tests": ["tests/test_access.py"]}])

    def test_each_test_runs_once(self):
        files = ["ACCESS.md", "api/ACCESS.md", "api/tests/test_access.py"]
        self.assertEqual(inventory.access(files, [])["suites"], [{"folder": "api", "tests": ["tests/test_access.py"]}])

    def test_named_tests_are_used_as_given(self):
        files = ["ACCESS.md", "checks/rules_spec.py"]
        self.assertEqual(inventory.access(files, ["checks/rules_spec.py"]), {"suites": [{"folder": ".", "tests": ["checks/rules_spec.py"]}], "not_checked": []})

    def test_named_tests_may_start_with_dot_slash(self):
        self.assertEqual(inventory.access(["tests/test_access.py"], ["./tests/test_access.py"])["not_checked"], [])

    def test_a_named_test_that_does_not_exist_is_not_checked(self):
        self.assertEqual(inventory.access(["ACCESS.md"], ["tests/gone.py"])["not_checked"], ["tests/gone.py"])

    def test_no_access_md_and_no_tests_needs_nothing(self):
        self.assertEqual(inventory.access(["app.py"], []), {"suites": [], "not_checked": []})


class TestsThatRan(unittest.TestCase):
    """Audit run 2: access tests that were all skipped must not count as run."""

    def junit(self, *cases):
        return "<testsuites><testsuite>" + "".join(cases) + "</testsuite></testsuites>"

    def test_passed_and_failed_tests_count(self):
        report = self.junit('<testcase name="a"/>', '<testcase name="b"><failure message="x"/></testcase>')
        self.assertEqual(inventory.tests_that_ran(report), 2)

    def test_skipped_tests_do_not_count(self):
        report = self.junit('<testcase name="a"><skipped message="no DATABASE_URL"/></testcase>',
                            '<testcase name="b"><skipped type="pytest.xfail" message="x"/></testcase>')
        self.assertEqual(inventory.tests_that_ran(report), 0)

    def test_an_unreadable_report_counts_nothing(self):
        self.assertEqual(inventory.tests_that_ran("not xml"), 0)


class Semgrep(unittest.TestCase):
    def test_every_file_semgrep_could_not_scan_is_not_checked(self):
        report = {
            "results": [],
            "errors": [
                {"level": "warn", "type": "Timeout", "path": "app.py"},
                {"level": "warn", "type": ["PartialParsing", []], "path": "big.py"},
                {"level": "error", "type": "Syntax error", "path": "broken.py"},
            ],
        }
        self.assertEqual(inventory.semgrep_not_scanned(report), ["app.py", "big.py", "broken.py"])

    def test_an_error_without_a_file_means_the_scan_itself_failed(self):
        self.assertEqual(inventory.semgrep_not_scanned({"errors": [{"level": "error", "type": "Rule parse error"}]}), ["the scan (Rule parse error)"])


class Settings(unittest.TestCase):
    def test_scanner_settings_files_are_listed_as_ignored(self):
        files = [".gitleaks.toml", ".gitleaksignore", "web/.npmrc", ".semgrepignore", "app.py"]
        found = inventory.settings(files, lambda path: "")
        self.assertEqual(found["ignored"], [".gitleaks.toml", ".gitleaksignore", ".semgrepignore", "web/.npmrc"])

    def test_inline_skip_comments_are_listed(self):
        texts = {"app.py": "x = 1\ntoken = 'abc'  # gitleaks:allow\n", "run.py": "eval(x)  # nosemgrep\nexec(y)  # nosem\n"}
        found = inventory.settings(list(texts), texts.get)
        self.assertEqual(found["skip_comments"], ["app.py:2 (gitleaks:allow)", "run.py:1 (nosem)", "run.py:2 (nosem)"])


if __name__ == "__main__":
    unittest.main()
