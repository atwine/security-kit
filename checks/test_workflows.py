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

import re
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


if __name__ == "__main__":
    unittest.main()
