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


if __name__ == "__main__":
    unittest.main()
