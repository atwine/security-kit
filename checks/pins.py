"""Check that every library, action, image and hook is pinned to one exact version.

    python checks/pins.py [folder] [--report findings.json]

Fails (exit 1) when it finds:
- a Python requirement without an exact version (`==` and a literal
  version), including in files pulled in with -r or -c, and in
  pyproject.toml's [project].dependencies;
- an editable or direct install from a branch or tag instead of a commit, or
  an archive URL without its hash;
- a second package source (--extra-index-url, --find-links) in a file whose
  requirements aren't all hash-pinned, so a same-named package elsewhere can
  win (how a fake `torchtriton` reached PyTorch users in December 2022);
- a requirements option the check doesn't know, so nothing slips through
  unread;
- a `package.json` with no lockfile next to it;
- a GitHub workflow or composite action whose `uses:` isn't pinned to a full
  commit SHA, or whose container or service image has no digest;
- a Dockerfile base image without a digest;
- a pre-commit hook pinned by a tag instead of a commit.

A single replacement source (--index-url) is allowed and printed as a note.
Requirements files are read the way pip reads them: a comment line never
joins the next line, and comments end at " #". The folder (default: the
repository root) limits the Python, JavaScript, Dockerfile and pre-commit
checks; workflows are read from `.github/workflows/` and composite actions
from anywhere in the repository. `--report` also writes the findings to a
JSON file, which the kit's self-test reads.
"""

import argparse
import json
import posixpath
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

# Folders that never hold the project's own dependency files. A virtual
# environment is recognised by an untracked pyvenv.cfg, so a pyvenv.cfg
# committed to the repository can't hide a folder.
SKIP_DIRS = {".git", "node_modules", "__pycache__", "site-packages"}
EXACT_PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*===?\s*[0-9][0-9A-Za-z.!+_-]*\s*(;.*)?$")
FULL_SHA = re.compile(r"@[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")
FRAGMENT_HASH = re.compile(r"(^|&)(sha256|sha384|sha512)=[0-9a-fA-F]+")
SCHEME_OR_VCS = re.compile(r"^([a-z][a-z0-9+.-]*://|(git|hg|svn|bzr)\+)", re.I)
VCS = re.compile(r"^(git|hg|svn|bzr)\+", re.I)
DIRECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\[\],-]*\s*@\s*(\S+)$")
COMMENT = re.compile(r"(^|\s+)#.*$")
INCLUDES = {"-r", "--requirement", "-c", "--constraint"}
EDITABLE = {"-e", "--editable"}
SECOND_SOURCES = {"--extra-index-url", "--extra-index", "--find-links", "-f"}
REPLACEMENT_SOURCES = {"--index-url", "-i"}
TRUSTED_HOST = {"--trusted-host"}
FLAGS = {"--prefer-binary", "--require-hashes", "--pre", "--no-index"}
WITH_VALUE = {"--only-binary", "--no-binary", "--hash", "--config-settings", "--global-option", "--use-feature"}
TAKES_VALUE = INCLUDES | EDITABLE | SECOND_SOURCES | REPLACEMENT_SOURCES | TRUSTED_HOST | WITH_VALUE
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
# A YAML key may be quoted ("uses": ...), so the key allows quotes, as REV does.
USES = re.compile(r"['\"]?\buses\b['\"]?\s*:\s*['\"]?([^'\"\s#,}]*)")
IMAGE = re.compile(r"['\"]?\b(?:image|container)\b['\"]?\s*:\s*['\"]?([^'\"\s#{},]+)")
REV = re.compile(r"['\"]?\brev\b['\"]?\s*:\s*['\"]?([^'\"\s,}#]+)")


def is_virtualenv(folder: Path) -> bool:
    marker = folder / "pyvenv.cfg"
    if not marker.is_file():
        return False
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", "--", str(marker)], capture_output=True)
    return tracked.returncode != 0


def files(root: Path, pattern: str):
    """Files under root, skipping only folders below root (never root's own path)."""
    for path in sorted(root.rglob(pattern)):
        folders = path.relative_to(root).parts[:-1]
        if SKIP_DIRS.intersection(folders):
            continue
        if any(is_virtualenv(root.joinpath(*folders[: depth + 1])) for depth in range(len(folders))):
            continue
        yield path


def pip_lines(text: str) -> list[tuple[int, str]]:
    """Requirement lines exactly as pip reads them: (first line number, text without comments)."""
    joined, buffer, start = [], [], 0
    for number, line in enumerate(text.lstrip("﻿").splitlines(), start=1):
        is_comment = COMMENT.match(line) is not None
        if not line.endswith("\\") or is_comment:
            if is_comment:
                line = " " + line
            if buffer:
                buffer.append(line)
                joined.append((start, "".join(buffer)))
                buffer = []
            else:
                joined.append((number, line))
        else:
            if not buffer:
                start = number
            buffer.append(line.strip("\\"))  # pip strips backslashes from both ends
    if buffer:
        joined.append((start, "".join(buffer)))
    lines = []
    for number, line in joined:
        line = COMMENT.sub("", line).strip()
        if line:
            lines.append((number, line))
    return lines


def _split(line: str) -> tuple[str, str]:
    """pip's split: words before the first one starting with '-', then the options."""
    tokens = line.split(" ")
    for index, token in enumerate(tokens):
        if token.startswith("-"):
            return " ".join(tokens[:index]).strip(), " ".join(tokens[index:])
    return line.strip(), ""


def _options(text: str) -> list[tuple[str, str]]:
    """(option, value) pairs, read the way pip's option parser reads them."""
    try:
        tokens = shlex.split(text)
    except ValueError:
        return [("(unreadable options)", text)]
    found, index = [], 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("--") and "=" in token:
            name, value = token.split("=", 1)
            index += 1
        elif token in TAKES_VALUE:
            name, value = token, tokens[index + 1] if index + 1 < len(tokens) else ""
            index += 2
        elif len(token) > 2 and not token.startswith("--") and token[:2] in TAKES_VALUE:
            name, value = token[:2], token[2:]
            index += 1
        else:
            name, value = token, ""
            index += 1
        found.append((name, value))
    return found


def _url_problem(url: str, hashed: bool) -> str:
    """Why a direct or editable URL isn't pinned, or '' when it is."""
    if VCS.match(url):
        return "" if FULL_SHA.search(url.split("#", 1)[0]) else "a version-control install not pinned to a full commit hash"
    if FRAGMENT_HASH.search(url.partition("#")[2]) or hashed:
        return ""
    return "a download without its hash (add #sha256=... or --hash)"


def _walk(path: str, read, state: dict, where: str = "") -> None:
    if path in state["seen"]:
        return
    state["seen"].add(path)
    try:
        text = read(path)
    except OSError:
        state["findings"].append(f"{where or path}: {'includes ' + path + ', which' if where else 'it'} doesn't exist or can't be read")
        return
    for number, line in pip_lines(text):
        here = f"{path}:{number}"
        requirement, option_text = _split(line)
        options = _options(option_text)
        hashed = any(name == "--hash" for name, _ in options)
        for name, value in options:
            if name in INCLUDES:
                if SCHEME_OR_VCS.match(value):
                    state["findings"].append(f"{here}: pulls in {value} from a URL, which can change at any time")
                else:
                    _walk(posixpath.normpath(posixpath.join(posixpath.dirname(path), value)), read, state, here)
            elif name in EDITABLE:
                problem = _url_problem(value, False) if SCHEME_OR_VCS.match(value) else ""
                if problem:
                    state["findings"].append(f"{here}: `-e {value}` is {problem}")
            elif name in SECOND_SOURCES:
                state["second_sources"].append(here)
            elif name in REPLACEMENT_SOURCES:
                state["notes"].append(f"{here}: installs from {value} instead of PyPI")
            elif name in TRUSTED_HOST:
                state["findings"].append(f"{here}: --trusted-host {value} turns off certificate checks for that host")
            elif name not in FLAGS and name not in WITH_VALUE:
                state["findings"].append(f"{here}: `{name}` is a requirements option the pin check doesn't know, so it can't tell whether the pins hold")
        if not requirement:
            continue
        if not re.match(r"^[A-Za-z0-9./]", requirement):
            state["findings"].append(f"{here}: `{requirement}` isn't a requirement the pin check can read")
            continue
        named = requirement.split(";", 1)[0].strip()
        if named.startswith((".", "/")):
            pass  # the project itself, or a local folder or wheel
        elif SCHEME_OR_VCS.match(named) or DIRECT.match(named):
            url = named if SCHEME_OR_VCS.match(named) else DIRECT.match(named).group(1)
            problem = _url_problem(url, hashed)
            if problem:
                state["findings"].append(f"{here}: `{named}` is {problem}")
        elif not EXACT_PIN.match(named):
            state["findings"].append(f"{here}: `{named}` isn't pinned to one exact version (use == and a version)")
        if not hashed:
            state["unhashed"].append(here)


def requirement_problems(path: str, read, seen=None) -> tuple[list[str], list[str]]:
    """(findings, notes) for one requirements file and every file it pulls in.

    A second package source anywhere in the files pip reads together applies
    to all of them, so the hash rule is checked across the whole set.
    """
    state = {"seen": set() if seen is None else seen, "findings": [], "notes": [], "second_sources": [], "unhashed": []}
    _walk(path, read, state)
    if state["second_sources"] and state["unhashed"]:
        state["findings"] += [
            f"{where}: a second package source while some requirements read with it have no hash pins; a same-named package there can win"
            for where in state["second_sources"]
        ]
    return state["findings"], state["notes"]


def workflow_problems(path: str, text: str) -> list[str]:
    findings, lines = [], text.splitlines()
    inside_with = None  # indentation of the `with:` key while reading its block
    for index, raw in enumerate(lines):
        number = index + 1
        if raw.lstrip().startswith("#") or not raw.strip():
            continue
        line = re.sub(r"\s+#.*$", "", raw)
        indent = len(line) - len(line.lstrip(" -"))
        if inside_with is not None and indent <= inside_with:
            inside_with = None
        for match in USES.finditer(line):
            target = match.group(1)
            if target in ("", ">", ">-", "|", "|-"):
                following = [l.strip() for l in lines[index + 1 :] if l.strip()]
                target = following[0].strip("'\"") if following else ""
            if not target or target.startswith(("./", "$")):
                continue
            if target.startswith("docker://"):
                if not DIGEST.search(target):
                    findings.append(f"{path}:{number}: `{target}` isn't pinned to an image digest (@sha256:...)")
            elif not FULL_SHA.search(target):
                findings.append(f"{path}:{number}: `{target}` isn't pinned to a full commit SHA; tags can be moved")
        if inside_with is None:
            for image in IMAGE.finditer(line):
                value = image.group(1)
                if value.startswith(("$", "./")) or value.endswith("Dockerfile"):
                    continue
                if not DIGEST.search(value):
                    findings.append(f"{path}:{number}: image `{value.removeprefix('docker://')}` isn't pinned to a digest (@sha256:...); tags can be moved")
        if re.match(r"^\s*(?:-\s*)?with\s*:\s*$", line):
            inside_with = len(line) - len(line.lstrip(" -"))
    return findings


def _expand(value: str, variables: dict) -> str | None:
    """A Dockerfile value with ${NAME} and $NAME filled from ARG defaults, or None when it can't be."""
    unresolved = False

    def fill(match):
        nonlocal unresolved
        name = match.group(1) or match.group(2)
        if name not in variables:
            unresolved = True
            return ""
        return variables[name]

    if re.search(r"\$\{[^}]*[:?+-][^}]*\}", value):
        return None  # ${NAME:-default} and friends depend on what's passed in
    result = re.sub(r"\$\{(\w+)\}|\$(\w+)", fill, value)
    return None if unresolved else result


def dockerfile_problems(path: str, text: str) -> list[str]:
    findings, stages, variables = [], set(), {}
    logical, buffer, start = [], "", 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1] + " "
            continue
        logical.append((start, buffer + line))
        buffer = ""
    if buffer:
        logical.append((start, buffer))

    def reference(where: int, value: str, what: str) -> None:
        if value.lower() in stages or value.isdigit():
            return
        resolved = _expand(value, variables)
        if resolved is None:
            findings.append(f"{path}:{where}: {what} `{value}` comes from a build variable, so the check can't tell it's pinned")
        elif resolved != "scratch" and resolved.lower() not in stages and not DIGEST.search(resolved):
            findings.append(f"{path}:{where}: {what} `{resolved}` isn't pinned to a digest (@sha256:...)")

    for number, line in logical:
        parts = line.split()
        if not parts:
            continue
        instruction = parts[0].upper()
        if instruction == "ARG":
            for part in parts[1:]:
                if "=" in part:
                    name, value = part.split("=", 1)
                    variables[name] = value.strip("'\"")
        elif instruction == "FROM":
            words = [part for part in parts[1:] if not part.startswith("--")]
            if words:
                reference(number, words[0], "base image")
                if len(words) >= 3 and words[1].upper() == "AS":
                    stages.add(words[2].lower())
        elif instruction in ("COPY", "ADD"):
            for part in parts[1:]:
                if part.startswith("--from="):
                    reference(number, part[len("--from="):], "image copied from")
        elif instruction == "RUN":
            for part in parts[1:]:
                if part.startswith("--mount="):
                    for setting in part[len("--mount="):].split(","):
                        if setting.startswith("from="):
                            reference(number, setting[len("from="):], "image mounted from")
    return findings


def precommit_problems(path: str, text: str) -> list[str]:
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        for match in REV.finditer(line):
            if not re.fullmatch(r"[0-9a-f]{40}", match.group(1)):
                findings.append(f"{path}:{number}: a hook is pinned to `{match.group(1)}`, which can be moved; use the commit (pre-commit autoupdate --freeze)")
    return findings


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8-sig", errors="replace")


def pyproject_problems(path: str, text: str) -> list[str]:
    """Libraries in [project].dependencies that aren't pinned to one exact version."""
    try:
        project = tomllib.loads(text).get("project", {})
    except tomllib.TOMLDecodeError as error:
        return [f"{path}: can't be read ({error}), so its libraries weren't checked"]
    dependencies = project.get("dependencies", []) if isinstance(project, dict) else []
    return [
        f"{path}: `{dependency}` isn't pinned to one exact version (use ==)"
        for dependency in dependencies
        if not isinstance(dependency, str) or not EXACT_PIN.match(dependency.strip())
    ]


def requirement_files_problems(paths: list[str], read) -> tuple[list[str], list[str]]:
    """Each requirements file is checked as its own pip install, with the files it includes.

    Every file gets its own record of files already read, so a file that was
    also checked on its own still counts for the file that includes it.
    """
    findings: list[str] = []
    notes: list[str] = []
    for path in paths:
        more, extra = requirement_problems(path, read, set())
        findings += more
        notes += extra
    return findings, notes


def _posix(path: Path) -> str:
    return path.as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check that libraries, actions, images and hooks are pinned to exact versions.")
    parser.add_argument("folder", nargs="?", default=".")
    parser.add_argument("--report", help="also write the findings to this JSON file")
    args = parser.parse_args()
    root = Path(args.folder)
    requirement_files = [
        _posix(path) for path in files(root, "*.txt") if "requirements" in path.name or path.parent.name == "requirements"
    ]
    findings, notes = requirement_files_problems(requirement_files, _read)
    for path in files(root, "pyproject.toml"):
        findings += pyproject_problems(_posix(path), _read(_posix(path)))
    for manifest in files(root, "package.json"):
        if not any((manifest.parent / lockfile).exists() for lockfile in LOCKFILES):
            findings.append(f"{_posix(manifest)}: no lockfile next to it, so each install can resolve different versions")
    workflows = Path(".github/workflows")
    if workflows.is_dir():
        for path in sorted(list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml"))):
            findings += workflow_problems(_posix(path), _read(_posix(path)))
    for path in list(files(Path("."), "action.yml")) + list(files(Path("."), "action.yaml")):
        findings += workflow_problems(_posix(path), _read(_posix(path)))
    for path in files(root, "Dockerfile*"):
        findings += dockerfile_problems(_posix(path), _read(_posix(path)))
    for path in files(root, ".pre-commit-config.yaml"):
        findings += precommit_problems(_posix(path), _read(_posix(path)))
    findings = list(dict.fromkeys(findings))
    for note in notes:
        print(f"note: {note}")
    for finding in findings:
        print(finding)
    print(f"{len(findings)} unpinned item(s)" if findings else "Everything is pinned.")
    if args.report:
        Path(args.report).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
