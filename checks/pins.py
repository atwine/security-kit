"""Check that every library, action, image and hook is pinned to one exact version.

    python checks/pins.py [folder] [--report findings.json]

Fails (exit 1) when it finds:
- a Python requirement without an exact version (`==` and a literal
  version), including in files pulled in with -r or -c;
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
import sys
from pathlib import Path

# Folders that never hold the project's own dependency files. Virtual
# environments are recognised by their pyvenv.cfg instead of by name, so a
# project folder that happens to be called env or venv is still checked.
SKIP_DIRS = {".git", "node_modules", "__pycache__", "site-packages"}
EXACT_PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*===?\s*[0-9][0-9A-Za-z.!+_-]*\s*(;.*)?$")
COMMIT = re.compile(r"@[0-9a-f]{40}$")
ARCHIVE_HASH = re.compile(r"#(sha256|sha384|sha512)=[0-9a-fA-F]+")
DIRECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\[\],-]*\s*@\s*(\S+)")
COMMENT = re.compile(r"(^|\s+)#.*$")
INCLUDES = {"-r", "--requirement", "-c", "--constraint"}
EDITABLE = {"-e", "--editable"}
SECOND_SOURCES = {"--extra-index-url", "--extra-index", "--find-links", "-f"}
REPLACEMENT_SOURCES = {"--index-url", "-i"}
HARMLESS = {"--prefer-binary", "--only-binary", "--no-binary", "--require-hashes", "--pre", "--no-index"}
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
USES = re.compile(r"\buses\s*:\s*['\"]?([^'\"\s#,}]+)")
IMAGE = re.compile(r"^\s*(?:-\s*)?(?:image|container)\s*:\s*['\"]?([^'\"\s#{}]+)")
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


def pip_lines(text: str) -> list[tuple[int, str]]:
    """Requirement lines as pip reads them: (first line number, text without comments)."""
    joined, buffer, start = [], [], 0
    for number, line in enumerate(text.splitlines(), start=1):
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
            buffer.append(line[:-1])
    if buffer:
        joined.append((start, "".join(buffer)))
    lines = []
    for number, line in joined:
        line = COMMENT.sub("", line).strip()
        if line:
            lines.append((number, line))
    return lines


def _option(tokens: list[str]) -> tuple[str, str]:
    first = tokens[0]
    if first.startswith("--") and "=" in first:
        name, value = first.split("=", 1)
        return name, value
    return first, tokens[1] if len(tokens) > 1 else ""


def _url_problem(url: str, hashed: bool) -> str:
    """Why a direct or editable URL isn't pinned, or '' when it is."""
    if re.match(r"^(git|hg|svn|bzr)\+", url):
        return "" if COMMIT.search(url.split("#", 1)[0]) else "a version-control install not pinned to a full commit hash"
    if ARCHIVE_HASH.search(url) or hashed:
        return ""
    return "a download without its hash (add #sha256=... or --hash)"


def requirement_problems(path: str, read, seen=None) -> tuple[list[str], list[str]]:
    """(findings, notes) for one requirements file and every file it pulls in."""
    seen = set() if seen is None else seen
    if path in seen:
        return [], []
    seen.add(path)
    try:
        text = read(path)
    except (FileNotFoundError, IsADirectoryError):
        return [f"{path}: doesn't exist, so it couldn't be checked"], []
    findings, notes, second_sources, unhashed = [], [], [], []
    for number, line in pip_lines(text):
        tokens = line.split()
        where = f"{path}:{number}"
        if tokens[0].startswith("-") and not tokens[0].startswith("--hash"):
            option, value = _option(tokens)
            if option in INCLUDES:
                target = posixpath.normpath(posixpath.join(posixpath.dirname(path), value))
                more, extra = requirement_problems(target, read, seen)
                if more == [f"{target}: doesn't exist, so it couldn't be checked"]:
                    more = [f"{where}: includes {value}, which doesn't exist"]
                findings += more
                notes += extra
            elif option in EDITABLE:
                local = not re.search(r"^[a-z][a-z0-9+.-]*://|^(git|hg|svn|bzr)\+", value)
                problem = "" if local else _url_problem(value, False)
                if problem:
                    findings.append(f"{where}: `{line}` is {problem}")
            elif option in SECOND_SOURCES:
                second_sources.append(where)
            elif option in REPLACEMENT_SOURCES:
                notes.append(f"{where}: installs from {value} instead of PyPI")
            elif option not in HARMLESS:
                findings.append(f"{where}: `{option}` is a requirements option the pin check doesn't know, so it can't tell whether the pins hold")
            continue
        hashed = any(token.startswith("--hash") for token in tokens)
        requirement = line.split(" --hash", 1)[0].strip()
        direct = DIRECT.match(requirement)
        url = direct.group(1) if direct else (requirement if re.search(r"://|^(git|hg|svn|bzr)\+", requirement) else "")
        if url:
            problem = _url_problem(url, hashed)
            if problem:
                findings.append(f"{where}: `{requirement}` is {problem}")
        elif not EXACT_PIN.match(requirement):
            findings.append(f"{where}: `{requirement}` isn't pinned to one exact version (use == and a version)")
        if not hashed:
            unhashed.append(where)
    if second_sources and unhashed:
        findings += [f"{where}: a second package source without hash pins on every requirement; a same-named package there can win" for where in second_sources]
    return findings, notes


def workflow_problems(path: str, text: str) -> list[str]:
    findings = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        line = re.sub(r"\s+#.*$", "", raw)
        for match in USES.finditer(line):
            target = match.group(1)
            if target.startswith("./") or target.startswith("$"):
                continue
            if target.startswith("docker://"):
                if not DIGEST.search(target):
                    findings.append(f"{path}:{number}: `{target}` isn't pinned to an image digest (@sha256:...)")
            elif not FULL_SHA.search(target):
                findings.append(f"{path}:{number}: `{target}` isn't pinned to a full commit SHA; tags can be moved")
        image = IMAGE.match(line)
        if image and not image.group(1).startswith("$") and not DIGEST.search(image.group(1)):
            findings.append(f"{path}:{number}: image `{image.group(1)}` isn't pinned to a digest (@sha256:...); tags can be moved")
    return findings


def dockerfile_problems(path: str, text: str) -> list[str]:
    findings, stages = [], set()
    for number, line in enumerate(text.splitlines(), start=1):
        parts = line.split()
        if not parts or parts[0].upper() != "FROM":
            continue
        words = [part for part in parts[1:] if not part.startswith("--")]
        if not words:
            continue
        image = words[0]
        if image != "scratch" and image.lower() not in stages and not DIGEST.search(image):
            findings.append(f"{path}:{number}: base image `{image}` isn't pinned to a digest (@sha256:...)")
        if len(words) >= 3 and words[1].upper() == "AS":
            stages.add(words[2].lower())
    return findings


def precommit_problems(path: str, text: str) -> list[str]:
    findings, repo = [], ""
    for number, line in enumerate(text.splitlines(), start=1):
        named = re.match(r"^\s*-?\s*repo\s*:\s*['\"]?([^'\"\s#]+)", line)
        if named:
            repo = named.group(1)
        rev = re.match(r"^\s*rev\s*:\s*['\"]?([^'\"\s#]+)", line)
        if rev and repo not in ("local", "meta") and not re.fullmatch(r"[0-9a-f]{40}", rev.group(1)):
            findings.append(f"{path}:{number}: hook `{repo}` is pinned to `{rev.group(1)}`, which can be moved; use the commit (pre-commit autoupdate --freeze)")
    return findings


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _posix(path: Path) -> str:
    return path.as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check that libraries, actions, images and hooks are pinned to exact versions.")
    parser.add_argument("folder", nargs="?", default=".")
    parser.add_argument("--report", help="also write the findings to this JSON file")
    args = parser.parse_args()
    root = Path(args.folder)
    findings: list[str] = []
    notes: list[str] = []
    seen: set[str] = set()
    for path in files(root, "*.txt"):
        if "requirements" in path.name or path.parent.name == "requirements":
            more, extra = requirement_problems(_posix(path), _read, seen)
            findings += more
            notes += extra
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
