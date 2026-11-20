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

    def test_a_lockfile_next_to_a_project_is_covered(self):
        self.assertEqual(inventory.python(["svc/pyproject.toml", "svc/uv.lock"], lambda path: PROJECT)["not_checked"], [])


class Access(unittest.TestCase):
    def test_access_tests_are_found_by_name_next_to_access_md(self):
        files = ["ACCESS.md", "tests/test_route_access.py", "tests/test_other.py", "app.py"]
        self.assertEqual(inventory.access(files, []), {"suites": [{"folder": ".", "tests": ["tests/test_route_access.py"]}], "not_checked": []})

    def test_each_access_md_is_tested_from_its_own_folder(self):
        files = ["selftest/fixture-app/ACCESS.md", "selftest/fixture-app/tests/test_access.py"]
        self.assertEqual(inventory.access(files, [])["suites"], [{"folder": "selftest/fixture-app", "tests": ["tests/test_access.py"]}])

    def test_access_md_without_access_tests_is_not_checked(self):
        self.assertEqual(inventory.access(["ACCESS.md", "tests/test_other.py"], [])["not_checked"], ["ACCESS.md"])

    def test_named_tests_are_used_as_given(self):
        files = ["ACCESS.md", "checks/rules_spec.py"]
        self.assertEqual(inventory.access(files, ["checks/rules_spec.py"]), {"suites": [{"folder": ".", "tests": ["checks/rules_spec.py"]}], "not_checked": []})

    def test_a_named_test_that_does_not_exist_is_not_checked(self):
        self.assertEqual(inventory.access(["ACCESS.md"], ["tests/gone.py"])["not_checked"], ["tests/gone.py"])

    def test_no_access_md_and_no_tests_needs_nothing(self):
        self.assertEqual(inventory.access(["app.py"], []), {"suites": [], "not_checked": []})


class Settings(unittest.TestCase):
    def test_scanner_settings_files_are_listed_as_ignored(self):
        files = [".gitleaks.toml", ".gitleaksignore", "web/.npmrc", ".semgrepignore", "app.py"]
        found = inventory.settings(files, lambda path: "")
        self.assertEqual(found["ignored"], [".gitleaks.toml", ".gitleaksignore", ".semgrepignore", "web/.npmrc"])

    def test_inline_skip_comments_are_listed(self):
        texts = {"app.py": "x = 1\ntoken = 'abc'  # gitleaks:allow\n", "run.py": "eval(x)  # nosemgrep\n"}
        found = inventory.settings(list(texts), texts.get)
        self.assertEqual(found["skip_comments"], ["app.py:2 (gitleaks:allow)", "run.py:1 (nosemgrep)"])


if __name__ == "__main__":
    unittest.main()
