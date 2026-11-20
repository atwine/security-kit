"""Plant one known security defect into the fixture app, to prove a check catches it.

    python selftest/plant.py <defect> <app-folder>

Only the kit's self-test runs this, on a throwaway checkout inside a GitHub
runner. The fake token is generated at run time, so this repository never
stores a secret-shaped string.
"""

import json
import secrets
import string
import subprocess
import sys
from pathlib import Path


def secret(app: Path) -> None:
    # The GitHub personal-token shape gitleaks looks for: ghp_ plus 36 letters and digits.
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (app / "settings_local.py").write_text(f'GITHUB_TOKEN = "ghp_{body}"\n', encoding="utf-8")


def vulnerable_library(app: Path) -> None:
    # urllib3 1.26.4 has published holes (PYSEC-2021-108 and later). It has no
    # dependencies of its own, so it installs cleanly next to the fixture's
    # libraries and pip-audit really looks it up. (requests 2.19.1, planted
    # before, needs idna<2.8, which the fixture's libraries can't use, so pip
    # stopped before pip-audit checked anything.)
    with (app / "requirements.txt").open("a", encoding="utf-8") as requirements:
        requirements.write("urllib3==1.26.4\n")


def node_library(app: Path) -> None:
    # lodash 4.17.15 has published high-severity holes (command injection,
    # prototype pollution). npm audit reads only the lockfile, so nothing is
    # downloaded or installed.
    lodash = {
        "version": "4.17.15",
        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
        "integrity": "sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==",
        "license": "MIT",
    }
    project = {"name": "fixture-app", "version": "1.0.0", "private": True, "dependencies": {"lodash": "4.17.15"}}
    lockfile = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {"": {k: project[k] for k in ("name", "version", "dependencies")}, "node_modules/lodash": lodash},
    }
    (app / "package.json").write_text(json.dumps(project, indent=2) + "\n", encoding="utf-8")
    (app / "package-lock.json").write_text(json.dumps(lockfile, indent=2) + "\n", encoding="utf-8")


def risky_code(app: Path) -> None:
    (app / "run_command.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def run(command: str):\n"
        "    return subprocess.run(command, shell=True)\n"
        "\n"
        "\n"
        "def calculate(expression: str):\n"
        "    return eval(expression)\n",
        encoding="utf-8",
    )


def unpinned_library(app: Path) -> None:
    replace_once(app / "requirements.txt", "fastapi==", "fastapi>=")


def drop_headers(app: Path, *names: str) -> None:
    """Keep the header middleware, minus the named headers."""
    replace_once(
        app / "app.py",
        "from fastapi_security_headers import SecurityHeadersMiddleware  # noqa: E402",
        "from fastapi_security_headers import DEFAULT_HEADERS, SecurityHeadersMiddleware  # noqa: E402",
    )
    kept = f"{{k: v for k, v in DEFAULT_HEADERS.items() if k not in {set(names)!r}}}"
    replace_once(
        app / "app.py",
        "app.add_middleware(SecurityHeadersMiddleware)  # security-headers",
        f"app.add_middleware(SecurityHeadersMiddleware, headers={kept})  # security-headers",
    )


def missing_headers(app: Path) -> None:
    # The headers ZAP's own rules check; the kit's site policy check covers the rest.
    drop_headers(app, "content-security-policy", "x-frame-options", "x-content-type-options")


def site_no_hsts(app: Path) -> None:
    drop_headers(app, "strict-transport-security")


def site_no_referrer_permissions(app: Path) -> None:
    drop_headers(app, "referrer-policy", "permissions-policy")


def site_insecure_cookie(app: Path) -> None:
    # A cookie on every response with HttpOnly (so ZAP's own rule stays
    # quiet) but without Secure or SameSite.
    with (app / "app.py").open("a", encoding="utf-8") as code:
        code.write(
            '\n\n@app.middleware("http")\n'
            "async def set_session_cookie(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.set_cookie("session", "planted", httponly=True, secure=False, samesite=None)\n'
            "    return response\n"
        )


def site_redirect_cookie(app: Path) -> None:
    # The start page redirects; the page it leads to sets a cookie without
    # Secure or SameSite (HttpOnly set, so ZAP's own rule stays quiet).
    replace_once(
        app / "app.py",
        '@app.get("/", response_class=HTMLResponse)\ndef home() -> str:\n',
        "from fastapi import Response  # noqa: E402\n"
        "from fastapi.responses import RedirectResponse  # noqa: E402\n\n\n"
        '@app.get("/")\ndef start():\n    return RedirectResponse("/welcome", status_code=307)\n\n\n'
        '@app.get("/welcome", response_class=HTMLResponse)\ndef home(response: Response) -> str:\n'
        '    response.set_cookie("session", "planted", httponly=True, secure=False, samesite=None)\n',
    )


def site_cors_wildcard(app: Path) -> None:
    # Any other site may read this one's responses.
    with (app / "app.py").open("a", encoding="utf-8") as code:
        code.write('\n\nfrom fastapi.middleware.cors import CORSMiddleware  # noqa: E402\n\napp.add_middleware(CORSMiddleware, allow_origins=["*"])\n')


def unruled_route(app: Path) -> None:
    with (app / "app.py").open("a", encoding="utf-8") as code:
        code.write('\n\n@app.get("/admin/export")\ndef export_everything() -> dict:\n    return {"rows": []}\n')


# A project file that tries to fake the verdict. Python loads a json.py from the
# folder a script runs in before its own json module, so a step that runs
# `python -` from the project folder would run this instead: it reports every
# check as passed and stops the script.
FORGED_JSON = '''\
import os
import sys

CHECKS = ("secrets", "python_libraries", "node_libraries", "risky_code", "pins", "access_rules")
with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
    output.write("results={" + ", ".join(f'"{c}": "success"' for c in CHECKS) + "}\\n")
sys.exit(0)
'''


def forge_verdict(app: Path) -> None:
    # A real secret for gitleaks to find, plus the forging json.py at the
    # checkout root, where the scan's steps run.
    secret(app)
    Path("json.py").write_text(FORGED_JSON, encoding="utf-8")


def mask_failure(app: Path) -> None:
    # A real secret for gitleaks to find, plus project code that registers the
    # word "failure" as a secret. GitHub then drops every job output holding
    # that word, which hides failed checks from the record the verdict reads.
    # pytest loads this conftest.py when the access-rule check runs, and the
    # real access tests still run after it.
    secret(app)
    (app / "conftest.py").write_text('print("::add-mask::failure")\n', encoding="utf-8")


def hidden_folder_code(app: Path) -> None:
    # The risky code again, inside a folder named like the kit's own checkout.
    hidden = app / ".security-kit"
    hidden.mkdir()
    risky_code(hidden)


def pin_included_file(app: Path) -> None:
    # A loose pin in a file the requirements file pulls in with -r.
    with (app / "requirements.txt").open("a", encoding="utf-8") as requirements:
        requirements.write("-r more.txt\n")
    (app / "more.txt").write_text("requests>=2.31\n", encoding="utf-8")


def pin_workflow_image(app: Path) -> None:
    # A workflow that runs its job in a container image pinned only by tag.
    folder = Path(".github/workflows")
    (folder / "planted.yml").write_text(
        "on: workflow_dispatch\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: python:3.12\n    steps:\n      - run: python --version\n",
        encoding="utf-8",
    )


def pin_precommit_tag(app: Path) -> None:
    # A pre-commit hook pinned by a tag, which its owner can move.
    (app / ".pre-commit-config.yaml").write_text(
        "repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.30.1\n    hooks:\n      - id: gitleaks\n",
        encoding="utf-8",
    )


def env_folder_pin(app: Path) -> None:
    # A loose pin in an ordinary project folder that happens to be called env.
    folder = app / "env"
    folder.mkdir()
    (folder / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")


# Checks that used to pass without checking anything (review group B).


def npm_subfolder(app: Path) -> None:
    # The vulnerable lockfile in a subfolder, where a frontend usually lives.
    folder = app / "frontend"
    folder.mkdir()
    node_library(folder)


def yarn_lockfile(app: Path) -> None:
    # A JavaScript lockfile npm audit can't read: it must count as not checked.
    (app / "package.json").write_text('{"name": "fixture-app", "version": "1.0.0", "private": true}\n', encoding="utf-8")
    (app / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")


def pyproject_library(app: Path) -> None:
    # A Python project that lists its libraries in pyproject.toml, with no
    # requirements file at all.
    folder = app / "worker"
    folder.mkdir()
    (folder / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=61"]\nbuild-backend = "setuptools.build_meta"\n\n'
        '[project]\nname = "fixture-worker"\nversion = "0.1.0"\ndependencies = ["urllib3==1.26.4"]\n\n'
        "[tool.setuptools]\npy-modules = []\n",
        encoding="utf-8",
    )


def renamed_access_tests(app: Path) -> None:
    # A route with no access rule, and access tests under another name.
    unruled_route(app)
    (app / "tests" / "test_access.py").rename(app / "tests" / "test_route_access.py")


def missing_access_tests(app: Path) -> None:
    # ACCESS.md says who may call each route, but no test checks it.
    (app / "tests" / "test_access.py").unlink()


def gitleaks_config(app: Path) -> None:
    # A leaked token, plus a project gitleaks config that allows every path.
    secret(app)
    Path(".gitleaks.toml").write_text("[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['''.*''']\n", encoding="utf-8")


def semgrepignore(app: Path) -> None:
    # Risky code, plus a project .semgrepignore that hides it from Semgrep.
    risky_code(app)
    Path(".semgrepignore").write_text("selftest/\n", encoding="utf-8")


def npmrc_registry(app: Path) -> None:
    # A vulnerable lockfile, plus a project .npmrc that sends npm audit to a
    # registry that isn't there. (min-release-age keeps Semgrep's .npmrc rule
    # quiet, so only npm audit is tested.)
    node_library(app)
    (app / ".npmrc").write_text("registry=http://127.0.0.1:9/\nmin-release-age = 7\n", encoding="utf-8")


def gitattributes_secret(app: Path) -> None:
    # A leaked token in a file the project marks as binary, so git shows its
    # history as "Binary files differ" (an easy accident with data files).
    secret(app)
    with Path(".gitattributes").open("a", encoding="utf-8") as attributes:
        attributes.write(f"{(app / 'settings_local.py').as_posix()} -diff\n")


def gitignored_risky_code(app: Path) -> None:
    # Risky code in a file that is committed although .gitignore lists it.
    risky_code(app)
    target = (app / "run_command.py").as_posix()
    with Path(".gitignore").open("a", encoding="utf-8") as ignore:
        ignore.write(f"{target}\n")
    subprocess.run(["git", "add", "-f", "--", target], check=True)


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        sys.exit(f"expected exactly one {old!r} in {path}")
    path.write_text(text.replace(old, new), encoding="utf-8")


DEFECTS = {
    "secret": secret,
    "vulnerable-library": vulnerable_library,
    "node-library": node_library,
    "risky-code": risky_code,
    "unpinned-library": unpinned_library,
    "missing-headers": missing_headers,
    "unruled-route": unruled_route,
    "forge-verdict": forge_verdict,
    "mask-failure": mask_failure,
    "hidden-folder-code": hidden_folder_code,
    "env-folder-pin": env_folder_pin,
    "npm-subfolder": npm_subfolder,
    "yarn-lockfile": yarn_lockfile,
    "pyproject-library": pyproject_library,
    "renamed-access-tests": renamed_access_tests,
    "missing-access-tests": missing_access_tests,
    "gitleaks-config": gitleaks_config,
    "semgrepignore": semgrepignore,
    "npmrc-registry": npmrc_registry,
    "gitattributes-secret": gitattributes_secret,
    "gitignored-risky-code": gitignored_risky_code,
    "site-no-hsts": site_no_hsts,
    "site-no-referrer-permissions": site_no_referrer_permissions,
    "site-insecure-cookie": site_insecure_cookie,
    "site-cors-wildcard": site_cors_wildcard,
    "site-redirect-cookie": site_redirect_cookie,
    "pin-included-file": pin_included_file,
    "pin-workflow-image": pin_workflow_image,
    "pin-precommit-tag": pin_precommit_tag,
}

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in DEFECTS:
        sys.exit(f"usage: python selftest/plant.py <{'|'.join(DEFECTS)}> <app-folder>")
    DEFECTS[sys.argv[1]](Path(sys.argv[2]))
