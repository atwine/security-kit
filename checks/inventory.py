"""Find everything a project's checks must cover, run the checks on all of it, and say what couldn't be checked.

    python -I inventory.py npm-audit <working dir> <reports dir>
    python -I inventory.py pip-audit <working dir> <reports dir>
    python -I inventory.py access-tests <working dir> <reports dir> [test file ...]
    python -I inventory.py semgrep-errors <semgrep.json> <reports dir>
    python -I inventory.py settings <folder>

It works from the files git tracks, so it sees what the project committed,
not leftovers on the machine. Anything a check can't read (a yarn lockfile,
a poetry-only pyproject.toml, an ACCESS.md with no access tests, a file
Semgrep couldn't scan, a package pip-audit couldn't look up) is printed,
written to <reports dir>/not-checked.json, and fails that check.

npm audit runs on copies of package.json and the lockfile in an empty
folder, against the public registry, so a project .npmrc can't send it
elsewhere. Standard library only.
"""

import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parent))  # -I leaves the kit's own folder off the path
import findings  # noqa: E402

USAGE = """usage:
    inventory.py npm-audit <working dir> <reports dir>
    inventory.py pip-audit <working dir> <reports dir>
    inventory.py access-tests <working dir> <reports dir> [test file ...]
    inventory.py semgrep-errors <semgrep.json> <reports dir>
    inventory.py settings <folder>"""

NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
OTHER_JS_LOCKFILES = ("yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
PYTHON_LOCKFILE = re.compile(r"^(uv\.lock|poetry\.lock|Pipfile\.lock|pylock(\.[^/]+)?\.toml)$")
OTHER_PYTHON_MANIFESTS = ("setup.py", "setup.cfg", "Pipfile", "requirements.in")
REQUIREMENTS = re.compile(r"(^|/)([^/]*requirements[^/]*|requirements/[^/]+)\.txt$")
ACCESS_TEST = re.compile(r"^(test_[^/]*access[^/]*|[^/]*access[^/]*_test)\.py$")
IGNORED_SETTINGS = (".gitleaks.toml", ".gitleaksignore", ".semgrepignore", ".npmrc")
SKIP_COMMENTS = ("gitleaks:allow", "nosem")  # "nosem" also matches nosemgrep
NPM_REGISTRY = "https://registry.npmjs.org/"
PYTEST_LOCK = Path(__file__).resolve().parent / "pytest-requirements.txt"  # pytest and its libraries, hash-pinned


def _parent(path: str) -> str:
    return posixpath.dirname(path) or "."


def _name(path: str) -> str:
    return posixpath.basename(path)


def _under(path: str, folder: str) -> bool:
    return folder == "." or path.startswith(folder + "/")


def _read_disk(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def node(files: list[str]) -> dict:
    """Folders whose npm lockfile npm audit reads, and other JavaScript lockfiles it can't.

    A yarn, pnpm or bun lockfile is reported even next to an npm lockfile: npm
    audit reads only the npm one, and the other may pin different versions.
    A package.json with no lockfile at all is left to the pin check, which fails it.
    """
    audit = sorted({_parent(f) for f in files if _name(f) in NPM_LOCKFILES})
    not_checked = sorted(f for f in files if _name(f) in OTHER_JS_LOCKFILES)
    return {"audit": audit, "not_checked": not_checked}


def _pyproject_kind(text: str) -> str:
    """'project' when pip-audit can read its libraries, 'unreadable' when they're listed another way, else 'none'."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return "unreadable"
    project = data.get("project")
    if isinstance(project, dict):
        if "dependencies" in project.get("dynamic", []):
            return "unreadable"  # filled in at build time; pip-audit can't see them
        return "project" if project.get("dependencies") else "none"
    tool = data.get("tool", {})
    return "unreadable" if "poetry" in tool or "pdm" in tool else "none"


def python(files: list[str], read=_read_disk) -> dict:
    """Requirements files and pyproject projects pip-audit reads, and Python manifests it can't."""
    requirements = sorted(f for f in files if REQUIREMENTS.search(f))
    exported = {_parent(f) for f in requirements}
    projects, not_checked = [], []
    for f in sorted(f for f in files if _name(f) == "pyproject.toml"):
        kind = _pyproject_kind(read(f))
        if kind == "project":
            projects.append(_parent(f))
        elif kind == "unreadable":
            not_checked.append(f)
    readable = exported | set(projects)
    for f in files:
        name, folder = _name(f), _parent(f)
        # pip-audit resolves a pyproject afresh, so locked versions are audited
        # only through a requirements file exported next to the lockfile.
        if PYTHON_LOCKFILE.match(name) and folder not in exported:
            not_checked.append(f)
        elif name in OTHER_PYTHON_MANIFESTS and folder not in readable:
            not_checked.append(f)
    return {"requirements": requirements, "projects": projects, "not_checked": sorted(set(not_checked))}


def pip_audit_skips(report: dict, own: set) -> list[str]:
    """Packages pip-audit couldn't look up, except the project being audited itself."""

    def normal(name):
        return re.sub(r"[-_.]+", "-", str(name)).lower()

    own = {normal(name) for name in own}
    return [
        f"{dep['name']} ({dep['skip_reason']})"
        for dep in report.get("dependencies", [])
        if dep.get("skip_reason") and normal(dep.get("name")) not in own
    ]


def _run_folder(test: str, present: set, fallback: str) -> str:
    """The nearest folder above a test that holds requirements.txt or pyproject.toml."""
    folder = _parent(test)
    while True:
        prefix = "" if folder == "." else folder + "/"
        if f"{prefix}requirements.txt" in present or f"{prefix}pyproject.toml" in present:
            return folder
        if folder == ".":
            return fallback
        folder = _parent(folder)


def access(files: list[str], named: list[str], wd: str = ".") -> dict:
    """Access-test suites to run, each from its own folder, and what couldn't be tested.

    files are every tracked file in the repository. Named tests are relative
    to wd. Otherwise each ACCESS.md under wd, or at the repository root, needs
    access tests under its own folder or, failing that, anywhere under wd.
    """
    present = set(files)
    if named:
        paths = {name: posixpath.normpath(posixpath.join(wd, name)) for name in named}
        missing = sorted(posixpath.normpath(name) for name, path in paths.items() if path not in present)
        found = sorted(posixpath.relpath(path, wd) for path in paths.values() if path in present)
        return {"suites": [{"folder": wd, "tests": found}] if found else [], "not_checked": missing}
    rules = [f for f in files if _name(f) == "ACCESS.md" and (_under(f, wd) or _parent(f) == ".")]
    tests = sorted(f for f in files if ACCESS_TEST.match(_name(f)) and _under(f, wd))
    groups, assigned, not_checked = {}, set(), []
    # Deepest ACCESS.md first, so each test runs once, with the rules nearest it.
    for rule in sorted(rules, key=lambda f: (-f.count("/"), f)):
        folder = _parent(rule)
        mine = [t for t in tests if _under(t, folder)] or tests
        if not mine:
            not_checked.append(rule)
            continue
        for test in mine:
            if test not in assigned:
                assigned.add(test)
                run = _run_folder(test, present, folder if _under(test, folder) else wd)
                groups.setdefault(run, []).append(posixpath.relpath(test, run))
    suites = [{"folder": folder, "tests": sorted(found)} for folder, found in sorted(groups.items())]
    return {"suites": suites, "not_checked": sorted(not_checked)}


def semgrep_not_scanned(report: dict) -> list[str]:
    """Files Semgrep says it couldn't scan (timeouts, parse failures), and scan-wide errors."""
    found = set()
    for error in report.get("errors", []):
        kind = error.get("type")
        kind = kind[0] if isinstance(kind, list) and kind else kind
        if error.get("path"):
            found.add(str(error["path"]))
        elif error.get("level") == "error":
            found.add(f"the scan ({kind})")
    return sorted(found)


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
    """Add a check's not-checked items to reports/not-checked.json (write, then rename)."""
    target = reports / "not-checked.json"
    data = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {}
    data[check] = sorted(set(data.get(check, [])) | set(paths))
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, target)


def _not_checked(reports: Path, check: str, items: list[str], why: str) -> int:
    record_not_checked(reports, check, items)
    for item in items:
        print(f"Not checked: {item} ({why}). A check that can't look counts as failed.")
    return 1 if items else 0


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
    return status | _not_checked(reports, "node_libraries", found["not_checked"], "npm audit reads only package-lock.json and npm-shrinkwrap.json; delete this lockfile if the project doesn't use it")


def run_pip_audit(wd: str, reports: Path) -> int:
    found = python(tracked(wd))
    targets = [(["-r", f], f, set()) for f in found["requirements"]]
    for folder in found["projects"]:
        name = tomllib.loads(_read_disk(f"{folder}/pyproject.toml"))["project"].get("name", "")
        targets.append(([folder], f"{folder}/pyproject.toml", {name}))
    status, skipped = 0, []
    for number, (arguments, label, own) in enumerate(targets, start=1):
        report = reports / f"pip-audit-{number}.json"
        print(f"::group::pip-audit: {label}")
        code = subprocess.run(
            # -P keeps the project's own files (a json.py, say) off pip-audit's import path.
            [sys.executable, "-P", "-m", "pip_audit", "--progress-spinner", "off", "--format", "json", "--output", str(report), *arguments]
        ).returncode
        findings.show("pip-audit", report)
        print("::endgroup::")
        status |= code != 0
        if report.is_file():
            try:
                skipped += [f"{label}: {item}" for item in pip_audit_skips(json.loads(report.read_text(encoding="utf-8")), own)]
            except ValueError:
                skipped.append(f"{label}: unreadable report")
    if not targets and not found["not_checked"]:
        print("No Python libraries listed.")
    status |= _not_checked(reports, "python_libraries", found["not_checked"], "pip-audit can't read the libraries this lists")
    return status | _not_checked(reports, "python_libraries", skipped, "pip-audit couldn't look this package up")


def tests_that_ran(junit: str) -> int:
    """How many tests in a pytest JUnit report ran: skipped and xfailed ones don't count."""
    try:
        root = ElementTree.fromstring(junit)
    except ElementTree.ParseError:
        return 0
    return sum(1 for case in root.iter("testcase") if case.find("skipped") is None)


def run_access_tests(wd: str, reports: Path, named: list[str]) -> int:
    found = access(tracked("."), named, wd)
    status, empty = 0, []
    for number, suite in enumerate(found["suites"], start=1):
        folder = suite["folder"]
        print(f"::group::access tests: {folder}")
        try:
            if (Path(folder) / "requirements.txt").is_file():
                subprocess.run([sys.executable, "-P", "-m", "pip", "install", "--quiet", "-r", "requirements.txt"], cwd=folder, check=True)
            if subprocess.run([sys.executable, "-P", "-m", "pip", "show", "--quiet", "pytest"], capture_output=True).returncode != 0:
                subprocess.run(
                    [sys.executable, "-P", "-m", "pip", "install", "--quiet", "--require-hashes", "--no-deps", "-r", str(PYTEST_LOCK)], check=True
                )
        except subprocess.CalledProcessError as error:
            print(f"::error::Installing what the access tests in {folder} need failed ({error}).")
            status = 1
        report = (reports / f"access-tests-{number}.xml").resolve()
        # A project's pytest settings can't drop tests from the run (-o addopts=).
        code = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=", "--junitxml", str(report), "--", *suite["tests"]],
            cwd=folder,
        ).returncode
        print("::endgroup::")
        status |= code != 0
        ran = tests_that_ran(report.read_text(encoding="utf-8", errors="replace")) if report.is_file() else 0
        if not ran:
            empty.append(folder)
    if not found["suites"] and not found["not_checked"]:
        print("No ACCESS.md and no access tests named. The access-guard skill writes both.")
    status |= _not_checked(reports, "access_rules", found["not_checked"], "ACCESS.md has rules but no access tests check them")
    return status | _not_checked(reports, "access_rules", empty, "no access test ran here")


def semgrep_errors(report: Path, reports: Path) -> int:
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _not_checked(reports, "risky_code", [report.name], "Semgrep wrote no readable report")
    return _not_checked(reports, "risky_code", semgrep_not_scanned(data), "Semgrep couldn't scan it")


def print_settings(folder: str) -> int:
    found = settings(tracked(folder))
    lines = ["### Scanner settings in the project", ""]
    if found["ignored"]:
        lines.append("Ignored (the kit uses its own settings): " + ", ".join(f"`{f}`" for f in found["ignored"]))
    if found["skip_comments"]:
        lines.append("Inline skip comments, which the checks respect (only the current files are listed):")
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
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
