"""Tests of the shared workflows' step order. No network.

    python -m unittest discover -s checks -p "test_*.py" -v

actions/checkout empties a folder that already exists without .git before
it fetches into it. If the project were checked out first, a project folder
named .security-kit would be emptied by the kit's own fetch and then moved
away, so no check would see the project's files there. A planted defect
can't show this (the planter runs after both fetches), so these tests read
the workflows: in every job, the kit is fetched and moved out before the
project is checked out.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
KIT_FETCH = "repository: ${{ job.workflow_repository }}"


def jobs(text: str) -> dict[str, str]:
    """Each job's block of a workflow file, by job id."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def checkouts(block: str) -> list[tuple[int, bool]]:
    """(position, fetches the kit) for each actions/checkout step in a job."""
    found = []
    for match in re.finditer(r"uses: actions/checkout@", block):
        step = block[match.end() : match.end() + 400].split("\n      - ", 1)[0]
        found.append((match.start(), KIT_FETCH in step))
    return found


class KitFirst(unittest.TestCase):
    def test_every_job_fetches_and_moves_the_kit_before_the_project(self):
        for name in ("scans.yml", "site-scan.yml"):
            for job, block in jobs((WORKFLOWS / name).read_text(encoding="utf-8")).items():
                steps = checkouts(block)
                project = [position for position, is_kit in steps if not is_kit]
                if not project:
                    continue
                with self.subTest(workflow=name, job=job):
                    kit = [position for position, is_kit in steps if is_kit]
                    self.assertTrue(kit, "this job checks out the project but never fetches the kit")
                    self.assertLess(kit[0], project[0], "the project is checked out before the kit is fetched")
                    move = block.find('mv .security-kit "')
                    self.assertTrue(kit[0] < move < project[0], "the kit isn't moved out before the project is checked out")


class ToolPins(unittest.TestCase):
    """Group F: the kit's own tools are pinned by what the kit itself records."""

    def scans(self):
        return (WORKFLOWS / "scans.yml").read_text(encoding="utf-8")

    def test_gitleaks_is_checked_against_a_checksum_the_kit_records(self):
        text = self.scans()
        self.assertNotIn("checksums.txt", text, "the checksum must not come from the same release as the download")
        self.assertRegex(text, r"GITLEAKS_SHA256: [0-9a-f]{64}")

    def test_pip_audit_installs_from_the_kit_s_hashed_lock_file(self):
        text = self.scans()
        self.assertIn("--require-hashes", text)
        self.assertIn("checks/pip-audit-requirements.txt", text)
        lock = (WORKFLOWS.parents[1] / "checks" / "pip-audit-requirements.txt").read_text(encoding="utf-8")
        packages = [line for line in lock.splitlines() if line and not line.startswith((" ", "#"))]
        self.assertTrue(any(line.startswith("pip-audit==") for line in packages))
        for line in packages:
            self.assertIn("\\", line, f"{line} has no --hash continuation")

    def test_the_self_test_also_runs_every_week(self):
        text = (WORKFLOWS / "self-test.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"schedule:\s*\n\s*- cron:")


CHECK_NAME = "Check the kit's files are this workflow's own commit"


def steps(block: str) -> list[str]:
    """A job's steps, in order, each as its own text."""
    return re.split(r"\n      - ", "\n" + block.split("\n    steps:\n", 1)[1])[1:]


def check_body(step: str) -> str:
    lines = step.split("run: |\n", 1)[1].splitlines()
    return "\n".join(line[10:] for line in lines if line.startswith("          ") or not line.strip()).strip()


def kit_check_scripts() -> list[str]:
    """The commit check's script from every job that has one."""
    return [
        check_body(step)
        for name in ("scans.yml", "site-scan.yml", "score.yml")
        for block in jobs((WORKFLOWS / name).read_text(encoding="utf-8")).values()
        for step in steps(block)
        if step.startswith(f"name: {CHECK_NAME}")
    ]


def kit_check_script() -> str:
    return kit_check_scripts()[0]


def bash() -> str | None:
    """bash, avoiding Windows' WSL launcher, which may have no Linux to run."""
    if sys.platform != "win32":
        return shutil.which("bash")
    git = shutil.which("git")
    if not git:
        return None
    # Git for Windows: git is in cmd\ or mingw64\bin\, bash in bin\.
    for parent in Path(git).resolve().parents:
        if (parent / "bin" / "bash.exe").is_file():
            return str(parent / "bin" / "bash.exe")
    return None


class KitCommit(unittest.TestCase):
    """F6: every job checks that the kit files it fetched are the workflow's own commit."""

    def test_every_kit_fetch_is_followed_by_the_commit_check(self):
        for name in ("scans.yml", "site-scan.yml", "score.yml"):
            for job, block in jobs((WORKFLOWS / name).read_text(encoding="utf-8")).items():
                listed = steps(block)
                for index, step in enumerate(listed):
                    if "uses: actions/checkout@" not in step or KIT_FETCH not in step:
                        continue
                    with self.subTest(workflow=name, job=job):
                        path = re.search(r"path: (\S+)", step).group(1)
                        self.assertLess(index + 1, len(listed), "nothing follows the kit fetch")
                        check = listed[index + 1]
                        self.assertTrue(check.startswith(f"name: {CHECK_NAME}"), "the kit fetch isn't followed by the commit check")
                        self.assertIn(f"KIT_DIR: {path}\n", check)
                        self.assertIn("WANT_SHA: ${{ job.workflow_sha }}", check)
                        self.assertIn("WANT_REPO: ${{ job.workflow_repository }}", check)

    def test_every_job_runs_the_same_check(self):
        # The check can't live in a kit script, because the kit's files are what
        # it checks. So each job carries a copy, and the copies must not drift.
        scripts = kit_check_scripts()
        self.assertEqual(len(scripts), 5)
        self.assertEqual(len(set(scripts)), 1, "the jobs' copies of the commit check differ")

    def test_the_check_passes_only_the_workflow_s_own_commit(self):
        shell = bash()
        if not shell:
            self.skipTest("no bash here")
        script = kit_check_script()
        with tempfile.TemporaryDirectory() as folder:
            kit = Path(folder) / "kit"
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(kit)]
            subprocess.run(["git", "init", "-q", str(kit)], check=True)
            subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "kit"], check=True)
            subprocess.run([*git, "remote", "add", "origin", "https://github.com/owner/kit"], check=True)
            sha = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()

            def outcome(repo: str, want: str) -> int:
                env = {**os.environ, "WANT_REPO": repo, "WANT_SHA": want, "KIT_DIR": str(kit).replace("\\", "/"),
                       "GITHUB_SERVER_URL": "https://github.com"}
                return subprocess.run([shell, "-eo", "pipefail", "-c", script], env=env, capture_output=True).returncode

            self.assertEqual(outcome("owner/kit", sha), 0)
            self.assertNotEqual(outcome("owner/kit", "0" * 40), 0, "a different commit passed")
            self.assertNotEqual(outcome("owner/project", sha), 0, "another repository passed")
            self.assertNotEqual(outcome("", sha), 0, "an empty repository name passed")
            self.assertNotEqual(outcome("owner/kit", ""), 0, "an empty commit passed")


class ScoreJob(unittest.TestCase):
    """Step 2 of the reporting plan: one combined score per project run."""

    def test_the_template_scores_every_run_from_both_parts(self):
        text = (WORKFLOWS.parents[1] / "templates" / "security.yml").read_text(encoding="utf-8")
        block = jobs(text)["score"]
        self.assertIn("needs: [code, website]", block)
        self.assertIn("if: always()", block)
        self.assertIn("atwine/security-kit/.github/workflows/score.yml@KIT_SHA", block)
        self.assertIn("needs.code.outputs.results", block)
        self.assertIn("needs.website.outputs.results", block)


class Summaries(unittest.TestCase):
    """Step 1 of the reporting plan: each checks job writes what each check found to the run's summary."""

    def test_every_checks_job_writes_its_summary_even_after_a_failure(self):
        for name, job in (("scans.yml", "read"), ("scans.yml", "run"), ("site-scan.yml", "scan")):
            with self.subTest(workflow=name, job=job):
                block = jobs((WORKFLOWS / name).read_text(encoding="utf-8"))[job]
                step = next((s for s in steps(block) if s.startswith("name: What each check found")), None)
                self.assertIsNotNone(step, "no summary step")
                self.assertIn("if: always()", step)
                # The summary only reports; it must never fail the job.
                self.assertIn("continue-on-error: true", step)
                self.assertIn("GITHUB_STEP_SUMMARY", step)


if __name__ == "__main__":
    unittest.main()
