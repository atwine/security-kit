"""Check that every library and GitHub action is pinned to one exact version.

    python checks/pins.py [folder] [--report findings.json]

Fails (exit 1) when it finds:
- a Python requirement without an exact version (`==`), so each install can
  pull different code;
- a requirements file that adds a second package source
  (`--extra-index-url`) without hash pins, so a same-named package on the
  public index can win (how a fake `torchtriton` reached PyTorch users in
  December 2022);
- a `package.json` with no lockfile next to it;
- a GitHub workflow step whose `uses:` isn't pinned to a full commit SHA
  (tags can be moved; a SHA can't).

Warns, without failing, about Dockerfile `FROM` lines without a digest.

The folder (default: the repository root) limits the Python and JavaScript
checks. GitHub workflows are always read from `.github/workflows/`.
`--report` also writes the findings to a JSON file, which the kit's
self-test reads.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Folders that never hold the project's own dependency files. Virtual
# environments are recognised by their pyvenv.cfg instead of by name, so a
# project folder that happens to be called env or venv is still checked.
SKIP_DIRS = {".git", "node_modules", "__pycache__", "site-packages"}
EXACT_PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*===?\s*[^\s;,*]+\s*(;.*)?$")
DIRECT_REFERENCE = re.compile(r"@\s*\S*@?[0-9a-f]{40}\b")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
FULL_SHA = re.compile(r"@[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")


def is_virtualenv(folder: Path) -> bool:
    return (folder / "pyvenv.cfg").is_file()


def files(root: Path, pattern: str):
    """Files under root, skipping only folders below root (never root's own path)."""
    for path in sorted(root.rglob(pattern)):
        folders = path.relative_to(root).parts[:-1]
        if SKIP_DIRS.intersection(folders):
            continue
        if any(is_virtualenv(root.joinpath(*folders[: depth + 1])) for depth in range(len(folders))):
            continue
        yield path


def logical_lines(text: str):
    """Requirement lines with backslash continuations joined, numbered by their first line."""
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        if raw.rstrip().endswith("\\"):
            buffer += raw.rstrip()[:-1] + " "
            continue
        yield start, buffer + raw
        buffer = ""
    if buffer:
        yield start, buffer


def check_requirements(path: Path, findings: list[str]) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    hashed = "--hash=" in text
    for number, line in logical_lines(text):
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--extra-index-url") and not hashed:
            findings.append(f"{path}:{number}: a second package source without hash pins; a same-named package on the public index can win")
            continue
        if line.startswith("-"):
            continue
        requirement = line.split(" --hash=", 1)[0].strip()
        if DIRECT_REFERENCE.search(requirement):
            continue
        if not EXACT_PIN.match(requirement):
            findings.append(f"{path}:{number}: `{requirement}` isn't pinned to one exact version (use ==)")


def check_node(root: Path, findings: list[str]) -> None:
    for manifest in files(root, "package.json"):
        if not any((manifest.parent / lockfile).exists() for lockfile in LOCKFILES):
            findings.append(f"{manifest}: no lockfile next to it, so each install can resolve different versions")


def check_workflows(findings: list[str]) -> None:
    workflows = Path(".github/workflows")
    if not workflows.is_dir():
        return
    for path in sorted(list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml"))):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            match = USES.match(line)
            if not match:
                continue
            target = match.group(1)
            if target.startswith("./"):
                continue
            if target.startswith("docker://"):
                if not DIGEST.search(target):
                    findings.append(f"{path}:{number}: `{target}` isn't pinned to an image digest (@sha256:...)")
                continue
            if not FULL_SHA.search(target):
                findings.append(f"{path}:{number}: `{target}` isn't pinned to a full commit SHA; tags can be moved")


def warn_dockerfiles(root: Path) -> list[str]:
    warnings = []
    for path in files(root, "Dockerfile*"):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            parts = line.split()
            if len(parts) >= 2 and parts[0].upper() == "FROM" and not DIGEST.search(parts[1]) and parts[1] != "scratch":
                warnings.append(f"{path}:{number}: `{parts[1]}` has no image digest (warning only)")
    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Check that libraries and actions are pinned to exact versions.")
    parser.add_argument("folder", nargs="?", default=".")
    parser.add_argument("--report", help="also write the findings to this JSON file")
    args = parser.parse_args()
    root = Path(args.folder)
    findings: list[str] = []
    for path in files(root, "*requirements*.txt"):
        check_requirements(path, findings)
    check_node(root, findings)
    check_workflows(findings)
    for warning in warn_dockerfiles(root):
        print(f"warning: {warning}")
    for finding in findings:
        print(finding)
    print(f"{len(findings)} unpinned item(s)" if findings else "Everything is pinned.")
    if args.report:
        Path(args.report).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
