"""Find everything a project's checks must cover, run the checks on all of it, and say what couldn't be checked.

    python -I inventory.py npm-audit <working dir> <reports dir>
    python -I inventory.py pip-audit <working dir> <reports dir>
    python -I inventory.py access-tests <working dir> <reports dir> [test file ...]
    python -I inventory.py semgrep-errors <semgrep.json> <reports dir>
    python -I inventory.py settings <folder>

It works from the files git tracks, so it sees what the project committed,
not leftovers on the machine. Anything a check can't read (a yarn lockfile,
a poetry-only pyproject.toml, an ACCESS.md with no access tests) is printed,
written to <reports dir>/not-checked.json, and fails that check.

npm audit runs on copies of package.json and the lockfile in an empty
folder, against the public registry, so a project .npmrc can't send it
elsewhere. Standard library only.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))  # -I leaves the kit's own folder off the path
import findings  # noqa: E402

NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
OTHER_JS_LOCKFILES = ("yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
PYTHON_LOCKFILE = re.compile(r"^(uv\.lock|poetry\.lock|Pipfile\.lock|pylock(\.[^/]+)?\.toml)$")
REQUIREMENTS = re.compile(r"(^|/)([^/]*requirements[^/]*|requirements/[^/]+)\.txt$")
ACCESS_TEST = re.compile(r"^(test_[^/]*access[^/]*|[^/]*access[^/]*_test)\.py$")
IGNORED_SETTINGS = (".gitleaks.toml", ".gitleaksignore", ".semgrepignore", ".npmrc")
SKIP_COMMENTS = ("gitleaks:allow", "nosemgrep")
NPM_REGISTRY = "https://registry.npmjs.org/"
PYTEST = "pytest==9.2.0"


def _parent(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return parent


def _name(path: str) -> str:
    return PurePosixPath(path).name


def _read_disk(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def node(files: list[str]) -> dict:
    """Folders whose npm lockfile npm audit reads, and other JavaScript lockfiles it can't."""
    audit = sorted({_parent(f) for f in files if _name(f) in NPM_LOCKFILES})
    not_checked = sorted(f for f in files if _name(f) in OTHER_JS_LOCKFILES and _parent(f) not in audit)
    return {"audit": audit, "not_checked": not_checked}


def _pyproject_kind(text: str) -> str:
    """'project' when pip-audit can read its libraries, 'unreadable' when it lists libraries another way, else 'tools'."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return "unreadable"
    if "project" in data:
        return "project"
    if "poetry" in data.get("tool", {}) or "pdm" in data.get("tool", {}):
        return "unreadable"
    return "tools"


def python(files: list[str], read=_read_disk) -> dict:
    """Requirements files and pyproject projects pip-audit reads, and Python manifests it can't."""
    requirements = sorted(f for f in files if REQUIREMENTS.search(f))
    projects, not_checked = [], []
    for f in sorted(f for f in files if _name(f) == "pyproject.toml"):
        kind = _pyproject_kind(read(f))
        if kind == "project":
            projects.append(_parent(f))
        elif kind == "unreadable":
            not_checked.append(f)
    covered = set(projects) | {_parent(f) for f in requirements} | {_parent(f) for f in not_checked}
    not_checked += [f for f in files if PYTHON_LOCKFILE.match(_name(f)) and _parent(f) not in covered]
    return {"requirements": requirements, "projects": projects, "not_checked": sorted(not_checked)}


def access(files: list[str], named: list[str], wd: str = ".") -> dict:
    """Access-test suites to run, each from its own folder, and what couldn't be tested."""
    if named:
        present = set(files)
        full = {name: str(PurePosixPath(wd) / name) if wd != "." else name for name in named}
        missing = [name for name in named if full[name] not in present]
        found = [name for name in named if name not in missing]
        return {"suites": [{"folder": wd, "tests": found}] if found else [], "not_checked": missing}
    suites, not_checked = [], []
    for rules in sorted(f for f in files if _name(f) == "ACCESS.md"):
        folder = _parent(rules)
        prefix = "" if folder == "." else folder + "/"
        tests = sorted(f[len(prefix):] for f in files if f.startswith(prefix) and ACCESS_TEST.match(_name(f)))
        if tests:
            suites.append({"folder": folder, "tests": tests})
        else:
            not_checked.append(rules)
    return {"suites": suites, "not_checked": not_checked}


def settings(files: list[str], read=_read_disk) -> dict:
    """Scanner settings files the kit ignores, and inline skip comments it respects."""
    ignored = sorted(f for f in files if _name(f) in IGNORED_SETTINGS)
    comments = []
    for f in sorted(files):
        try:
            text = read(f) or ""
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for marker in SKIP_COMMENTS:
                if marker in line:
                    comments.append(f"{f}:{number} ({marker})")
    return {"ignored": ignored, "skip_comments": comments}


def tracked(folder: str) -> list[str]:
    """Files git tracks under folder, relative to the repository root."""
    out = subprocess.run(["git", "ls-files", "-z", "--", folder], capture_output=True, check=True).stdout
    return [path for path in out.decode("utf-8", "replace").split("\0") if path]


def record_not_checked(reports: Path, check: str, paths: list[str]) -> None:
    """Add a check's not-checked paths to reports/not-checked.json (write, then rename)."""
    target = reports / "not-checked.json"
    data = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {}
    data[check] = sorted(set(data.get(check, [])) | set(paths))
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, target)


def _report_not_checked(reports: Path, check: str, paths: list[str], why: str) -> int:
    record_not_checked(reports, check, paths)
    for path in paths:
        print(f"::error::Not checked: {path} ({why}). A check that can't look counts as failed.")
    return 1 if paths else 0


def run_npm(wd: str, reports: Path) -> int:
    found = node(tracked(wd))
    status = 0
    for number, folder in enumerate(found["audit"], start=1):
        report = reports / f"npm-audit-{number}.json"
        print(f"::group::npm audit: {folder}")
        with tempfile.TemporaryDirectory() as copy:
            for name in ("package.json", *NPM_LOCKFILES):
                if (Path(folder) / name).is_file():
                    shutil.copyfile(Path(folder) / name, Path(copy) / name)
            npm = shutil.which("npm") or "npm"
            with report.open("w", encoding="utf-8") as out:
                code = subprocess.run(
                    [npm, "audit", "--audit-level=high", "--omit=dev", "--json", f"--registry={NPM_REGISTRY}"], cwd=copy, stdout=out
                ).returncode
        findings.show("npm", report)
        print("::endgroup::")
        status |= code != 0
    if not found["audit"] and not found["not_checked"]:
        print("No npm lockfiles.")
    return status | _report_not_checked(reports, "node_libraries", found["not_checked"], "npm audit can't read this lockfile")


def run_pip_audit(wd: str, reports: Path) -> int:
    found = python(tracked(wd))
    targets = [(["-r", f], f) for f in found["requirements"]] + [([folder], f"{folder}/pyproject.toml") for folder in found["projects"]]
    status = 0
    for number, (arguments, label) in enumerate(targets, start=1):
        report = reports / f"pip-audit-{number}.json"
        print(f"::group::pip-audit: {label}")
        code = subprocess.run(
            # -P keeps the project's own files (a json.py, say) off pip-audit's import path.
            [sys.executable, "-P", "-m", "pip_audit", "--progress-spinner", "off", "--format", "json", "--output", str(report), *arguments]
        ).returncode
        findings.show("pip-audit", report)
        print("::endgroup::")
        status |= code != 0
    if not targets and not found["not_checked"]:
        print("No Python libraries listed.")
    return status | _report_not_checked(reports, "python_libraries", found["not_checked"], "pip-audit can't read the libraries this lists")


def run_access_tests(wd: str, reports: Path, named: list[str]) -> int:
    found = access(tracked(wd), named, wd)
    status = 0
    for number, suite in enumerate(found["suites"], start=1):
        folder = suite["folder"]
        print(f"::group::access tests: {folder}")
        if (Path(folder) / "requirements.txt").is_file():
            subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "-r", "requirements.txt"], cwd=folder, check=True)
        if subprocess.run([sys.executable, "-m", "pip", "show", "--quiet", "pytest"], capture_output=True).returncode != 0:
            subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", PYTEST], check=True)
        report = (reports / f"access-tests-{number}.xml").resolve()
        code = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", str(report), *suite["tests"]], cwd=folder
        ).returncode
        print("::endgroup::")
        status |= code != 0
    if not found["suites"] and not found["not_checked"]:
        print("No ACCESS.md and no access tests named. The access-guard skill writes both.")
    return status | _report_not_checked(reports, "access_rules", found["not_checked"], "ACCESS.md has rules but no access tests check them")


def semgrep_errors(report: Path, reports: Path) -> int:
    """Files Semgrep reported it couldn't scan, counted as not checked."""
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _report_not_checked(reports, "risky_code", [report.name], "Semgrep wrote no readable report")
    paths = sorted({str(error.get("path")) for error in data.get("errors", []) if error.get("level") == "error" and error.get("path")})
    return _report_not_checked(reports, "risky_code", paths, "Semgrep couldn't scan this file")


def print_settings(folder: str) -> int:
    found = settings(tracked(folder))
    lines = ["### Scanner settings in the project", ""]
    if found["ignored"]:
        lines.append("Ignored (the kit uses its own settings): " + ", ".join(f"`{f}`" for f in found["ignored"]))
    if found["skip_comments"]:
        lines.append("Inline skip comments, which the checks respect:")
        lines += [f"- `{comment}`" for comment in found["skip_comments"]]
    if len(lines) == 2:
        lines.append("None.")
    text = "\n".join(lines)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(text + "\n")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "npm-audit":
        return run_npm(argv[1], Path(argv[2]))
    if len(argv) == 3 and argv[0] == "pip-audit":
        return run_pip_audit(argv[1], Path(argv[2]))
    if len(argv) >= 3 and argv[0] == "access-tests":
        return run_access_tests(argv[1], Path(argv[2]), argv[3:])
    if len(argv) == 3 and argv[0] == "semgrep-errors":
        return semgrep_errors(Path(argv[1]), Path(argv[2]))
    if len(argv) == 2 and argv[0] == "settings":
        return print_settings(argv[1])
    print("\n".join(__doc__.strip().splitlines()[2:7]), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
