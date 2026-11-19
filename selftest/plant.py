"""Plant one known security defect into the fixture app, to prove a check catches it.

    python selftest/plant.py <defect> <app-folder>

Only the kit's self-test runs this, on a throwaway checkout inside a GitHub
runner. The fake token is generated at run time, so this repository never
stores a secret-shaped string.
"""

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


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        sys.exit(f"expected exactly one {old!r} in {path}")
    path.write_text(text.replace(old, new), encoding="utf-8")


DEFECTS = {
    "secret": secret,
    "vulnerable-library": vulnerable_library,
    "risky-code": risky_code,
    "unpinned-library": unpinned_library,
    "missing-headers": missing_headers,
    "unruled-route": unruled_route,
}

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in DEFECTS:
        sys.exit(f"usage: python selftest/plant.py <{'|'.join(DEFECTS)}> <app-folder>")
    DEFECTS[sys.argv[1]](Path(sys.argv[2]))
