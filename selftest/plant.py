"""Plant one known security defect into the fixture app, to prove a check catches it.

    python selftest/plant.py <defect> <app-folder>

Only the kit's self-test runs this, on a throwaway checkout inside a GitHub
runner. The fake token is generated at run time, so this repository never
stores a secret-shaped string.
"""

import json
import secrets
import string
import sys
from pathlib import Path


def secret(app: Path) -> None:
    # The GitHub personal-token shape gitleaks looks for: ghp_ plus 36 letters and digits.
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (app / "settings_local.py").write_text(f'GITHUB_TOKEN = "ghp_{body}"\n', encoding="utf-8")


def vulnerable_library(app: Path) -> None:
    # requests 2.19.1 has published holes, fixed in later releases.
    with (app / "requirements.txt").open("a", encoding="utf-8") as requirements:
        requirements.write("requests==2.19.1\n")


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


def missing_headers(app: Path) -> None:
    replace_once(
        app / "app.py",
        "app.add_middleware(SecurityHeadersMiddleware)  # security-headers",
        "# (the security headers were removed by the self-test)",
    )


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


def hidden_folder_code(app: Path) -> None:
    # The risky code again, inside a folder named like the kit's own checkout.
    hidden = app / ".security-kit"
    hidden.mkdir()
    risky_code(hidden)


def env_folder_pin(app: Path) -> None:
    # A loose pin in an ordinary project folder that happens to be called env.
    folder = app / "env"
    folder.mkdir()
    (folder / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")


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
    "hidden-folder-code": hidden_folder_code,
    "env-folder-pin": env_folder_pin,
}

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in DEFECTS:
        sys.exit(f"usage: python selftest/plant.py <{'|'.join(DEFECTS)}> <app-folder>")
    DEFECTS[sys.argv[1]](Path(sys.argv[2]))
