"""Tests for the pin check (checks/pins.py). No network.

    python -m unittest discover -s checks -p "test_*.py" -v

Each test gives the check some file text and checks what it reports. The
cases are the ones the phase 5 reviews reproduced as passing unnoticed.
"""

import unittest
from pathlib import Path

import pins

SHA = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
DIGEST = "sha256:" + "a" * 64


def requirements(files, start="requirements.txt"):
    def read(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]

    return pins.requirement_problems(start, read)


class Requirements(unittest.TestCase):
    def assert_flags(self, text, *pieces):
        findings, _ = requirements({"requirements.txt": text})
        self.assertTrue(findings, f"nothing reported for {text!r}")
        for piece in pieces:
            self.assertIn(piece, " ".join(findings))

    def assert_clean(self, text):
        self.assertEqual(requirements({"requirements.txt": text})[0], [])

    def test_exact_pins_pass(self):
        self.assert_clean("fastapi==0.165.0\nuvicorn[standard]==0.54.0 ; python_version >= '3.10'\n# a comment\n")

    def test_a_loose_pin_fails(self):
        self.assert_flags("fastapi>=0.165.0\n", "fastapi>=0.165.0")

    def test_a_version_taken_from_the_environment_fails(self):
        self.assert_flags("fastapi==${FASTAPI_VERSION}\n", "fastapi==${FASTAPI_VERSION}")

    def test_an_editable_install_from_a_branch_fails(self):
        self.assert_flags("-e git+https://github.com/org/lib.git@main#egg=lib\n", "git+https://github.com/org/lib.git@main")

    def test_an_editable_install_at_a_commit_passes(self):
        self.assert_clean(f"-e git+https://github.com/org/lib.git@{SHA}#egg=lib\n")

    def test_an_editable_local_folder_passes(self):
        self.assert_clean("-e .\n-e ./packages/core\n")

    def test_a_commit_hash_somewhere_else_in_a_url_does_not_count(self):
        self.assert_flags(f"lib @ git+https://github.com/org/lib.git@main#subdirectory={SHA}\n", "lib @")
        self.assert_flags(f"lib @ https://example.org/{SHA}/lib.tar.gz\n", "lib @")

    def test_a_direct_reference_at_a_commit_passes(self):
        self.assert_clean(f"lib @ git+https://github.com/org/lib.git@{SHA}\n")

    def test_an_archive_with_its_hash_passes(self):
        self.assert_clean(f"lib @ https://example.org/lib-1.0.tar.gz#sha256={'b' * 64}\n")

    def test_included_files_are_checked_too(self):
        findings, _ = requirements({"requirements.txt": "-r base.txt\n-c constraints.txt\nfastapi==0.165.0\n", "base.txt": "requests\n", "constraints.txt": "idna>=3\n"})
        self.assertEqual(sorted(f.split(":")[0] for f in findings), ["base.txt", "constraints.txt"])

    def test_an_included_file_that_does_not_exist_fails(self):
        self.assert_flags("-r missing.txt\n", "missing.txt")

    def test_an_include_loop_is_read_once(self):
        findings, _ = requirements({"requirements.txt": "-r requirements.txt\nfastapi==0.165.0\n"})
        self.assertEqual(findings, [])

    def test_a_second_package_source_without_hashes_fails(self):
        self.assert_flags("--extra-index-url https://pypi.example.org/simple\nlib==1.0\n", "second package source")
        self.assert_flags("--find-links https://example.org/wheels/\nlib==1.0\n", "second package source")
        self.assert_flags("--extra-index https://pypi.example.org/simple\nlib==1.0\n", "second package source")

    def test_hashes_mentioned_only_in_a_comment_do_not_count(self):
        self.assert_flags("--extra-index-url https://pypi.example.org/simple\nlib==1.0  # add --hash=sha256:x later\n", "second package source")

    def test_a_second_source_with_every_line_hashed_passes(self):
        self.assert_clean(f"--extra-index-url https://pypi.example.org/simple\nlib==1.0 --hash={DIGEST}\nother==2.0 \\\n    --hash={DIGEST}\n")

    def test_a_replacement_source_is_allowed_and_noted(self):
        findings, notes = requirements({"requirements.txt": "--index-url https://mirror.example.org/simple\nlib==1.0\n"})
        self.assertEqual(findings, [])
        self.assertIn("https://mirror.example.org/simple", " ".join(notes))

    def test_an_option_the_check_does_not_know_fails(self):
        self.assert_flags("--some-new-option value\nlib==1.0\n", "--some-new-option")

    def test_known_harmless_options_pass(self):
        self.assert_clean("--prefer-binary\n--only-binary :all:\n--require-hashes\nlib==1.0 --hash=" + DIGEST + "\n")

    def test_a_comment_ending_in_a_backslash_does_not_hide_the_next_line(self):
        # pip doesn't join a comment line with the next one.
        self.assert_flags("# old pins \\\nflask\n", "flask")

    def test_a_continued_requirement_is_read_whole(self):
        self.assert_clean(f"lib==1.0 \\\n    --hash={DIGEST}\n")


class RequirementBypasses(unittest.TestCase):
    """Inputs the group E reviews proved pip installs unpinned while the check passed."""

    def flags(self, files, start="requirements.txt"):
        findings, _ = requirements(files, start)
        self.assertTrue(findings, f"nothing reported for {files!r}")
        return " ".join(findings)

    def test_a_leading_backslash_on_a_continued_line_does_not_hide_an_option(self):
        self.flags({"requirements.txt": "\\-r https://evil.example/r.txt#sha256=ab \\\n\nrequests==2.31.0\n"})
        self.flags({"requirements.txt": "\\--index-url https://evil.example/simple/#sha256=ab \\\n\nrequests==2.31.0\n"})

    def test_a_marker_cannot_make_a_loose_pin_look_like_a_hashed_url(self):
        self.flags({"requirements.txt": 'requests>=0; sys_platform != "://#sha256=0"\n'})

    def test_every_option_on_a_line_is_read(self):
        self.assertIn("deps.txt", self.flags({"requirements.txt": "--prefer-binary -r deps.txt\n", "deps.txt": "requests\n"}))
        self.assertIn("deps.txt", self.flags({"requirements.txt": "--prefer-binary \\\n-r deps.txt\n", "deps.txt": "requests\n"}))

    def test_a_quoted_editable_url_is_still_a_url(self):
        self.flags({"requirements.txt": '-e "git+https://github.com/psf/requests@main#egg=requests"\n'})

    def test_a_second_source_counts_across_included_files(self):
        self.flags({"requirements.txt": "--extra-index-url https://evil.example/simple\n-r base.txt\n", "base.txt": "torchtriton==2.0.0\n"})
        self.flags({"requirements.txt": "-r sources.txt\ntorchtriton==2.0.0\n", "sources.txt": "--extra-index-url https://evil.example/simple\n"})

    def test_a_file_pulled_in_from_a_url_fails(self):
        self.assertIn("https://example.org/r.txt", self.flags({"requirements.txt": "-r https://example.org/r.txt\n"}))

    def test_turning_off_certificate_checks_fails_with_a_clear_reason(self):
        self.assertIn("certificate", self.flags({"requirements.txt": "--trusted-host mirror.example.org\nlib==1.0\n"}))


class RequirementFalseAlarms(unittest.TestCase):
    """Safe inputs the first version wrongly failed."""

    def clean(self, files, start="requirements.txt"):
        self.assertEqual(requirements(files, start)[0], [])

    def test_a_byte_order_mark_is_ignored(self):
        self.clean({"requirements.txt": "\ufefffastapi==0.165.0\n"})

    def test_options_after_a_requirement_are_read_as_options(self):
        self.clean({"requirements.txt": f"lib==1.0\t--hash={DIGEST}\nother==2.0 --config-settings=foo=bar\n"})

    def test_installing_the_project_itself_or_a_local_wheel_passes(self):
        self.clean({"requirements.txt": ".\n./packages/core\n./wheels/lib-1.0-py3-none-any.whl\n"})


class Workflows(unittest.TestCase):
    def test_every_spelling_of_uses_is_checked(self):
        text = f"steps:\n  - uses: actions/checkout@v4\n  - {{uses: actions/cache@v4}}\n  - name: x\n    uses: 'org/act@{SHA}'\n"
        found = pins.workflow_problems(".github/workflows/ci.yml", text)
        self.assertEqual(len(found), 2)
        self.assertIn("actions/cache@v4", " ".join(found))

    def test_container_and_service_images_need_a_digest(self):
        text = f"jobs:\n  a:\n    container: python:3.12\n    services:\n      db:\n        image: postgres:16\n      cache:\n        image: redis@{DIGEST}\n"
        found = pins.workflow_problems(".github/workflows/ci.yml", text)
        self.assertEqual(len(found), 2)
        self.assertIn("python:3.12", " ".join(found))
        self.assertIn("postgres:16", " ".join(found))

    def test_a_container_given_as_a_mapping_checks_its_image(self):
        text = "jobs:\n  a:\n    container:\n      image: node:22\n"
        self.assertIn("node:22", " ".join(pins.workflow_problems("action.yml", text)))

    def test_a_flow_style_container_and_a_value_on_the_next_line_are_read(self):
        text = "jobs:\n  a:\n    container: {image: node:18}\n    steps:\n      - uses: >-\n          actions/cache@v4\n"
        found = " ".join(pins.workflow_problems(".github/workflows/ci.yml", text))
        self.assertIn("node:18", found)
        self.assertIn("actions/cache@v4", found)

    def test_an_image_input_to_an_action_is_not_a_container(self):
        text = f"steps:\n  - uses: anchore/scan-action@{SHA}\n    with:\n      image: myapp:latest\n"
        self.assertEqual(pins.workflow_problems(".github/workflows/ci.yml", text), [])

    def test_a_docker_action_built_from_its_dockerfile_passes(self):
        self.assertEqual(pins.workflow_problems("action.yml", "runs:\n  using: docker\n  image: Dockerfile\n"), [])

    def test_local_actions_and_expressions_are_left_alone(self):
        text = "steps:\n  - uses: ./.github/actions/setup\n    container: ${{ matrix.image }}\n"
        self.assertEqual(pins.workflow_problems(".github/workflows/ci.yml", text), [])


class Dockerfiles(unittest.TestCase):
    def test_a_base_image_without_a_digest_fails(self):
        self.assertIn("python:3.12", " ".join(pins.dockerfile_problems("Dockerfile", "FROM --platform=linux/amd64 python:3.12\n")))

    def test_a_base_image_from_a_variable_uses_the_variable_s_value(self):
        text = "ARG IMG=python:latest\nFROM ${IMG:-python@" + DIGEST + "}\n"
        self.assertTrue(pins.dockerfile_problems("Dockerfile", text))
        self.assertEqual(pins.dockerfile_problems("Dockerfile", "ARG IMG=python@" + DIGEST + "\nFROM ${IMG}\n"), [])

    def test_images_copied_or_mounted_from_need_a_digest(self):
        text = "FROM python@" + DIGEST + " AS build\nCOPY --from=nginx:latest /a /b\nCOPY --from=build /c /d\nRUN --mount=type=bind,from=alpine:latest,target=/m true\n"
        found = pins.dockerfile_problems("Dockerfile", text)
        self.assertEqual(len(found), 2)
        self.assertIn("nginx:latest", " ".join(found))
        self.assertIn("alpine:latest", " ".join(found))

    def test_lowercase_instructions_and_continued_lines_are_read(self):
        self.assertTrue(pins.dockerfile_problems("Dockerfile", "from \\\n  python:3.12\n"))

    def test_digests_scratch_and_earlier_stages_pass(self):
        text = f"FROM python:3.12@{DIGEST} AS build\nFROM scratch\nFROM build\nCOPY --from=build /a /a\n"
        self.assertEqual(pins.dockerfile_problems("Dockerfile", text), [])


class PreCommit(unittest.TestCase):
    def test_a_hook_pinned_by_tag_fails(self):
        text = "repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.30.1\n"
        self.assertIn("v8.30.1", " ".join(pins.precommit_problems(".pre-commit-config.yaml", text)))

    def test_every_spelling_of_rev_is_checked(self):
        text = (
            "repos:\n  - rev: v4.6.0\n    repo: https://github.com/pre-commit/pre-commit-hooks\n"
            "  - {repo: https://github.com/psf/black, rev: 24.4.2, hooks: [{id: black}]}\n"
            '  - "repo": https://github.com/astral-sh/ruff-pre-commit\n    "rev": v0.4.4\n'
        )
        found = " ".join(pins.precommit_problems(".pre-commit-config.yaml", text))
        for tag in ("v4.6.0", "24.4.2", "v0.4.4"):
            self.assertIn(tag, found)

    def test_a_frozen_hook_and_local_hooks_pass(self):
        text = f"repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: {SHA}  # frozen: v8.30.1\n  - repo: local\n    hooks: []\n"
        self.assertEqual(pins.precommit_problems(".pre-commit-config.yaml", text), [])


class FolderWalk(unittest.TestCase):
    def test_a_committed_pyvenv_cfg_does_not_hide_a_folder(self):
        import os
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            subprocess.run(["git", "init", "-q", folder], check=True)
            (Path(folder) / "backend").mkdir()
            (Path(folder) / "backend" / "pyvenv.cfg").write_text("", encoding="utf-8")
            (Path(folder) / "backend" / "requirements.txt").write_text("requests\n", encoding="utf-8")
            subprocess.run(["git", "-C", folder, "add", "-A"], check=True)
            here = os.getcwd()
            os.chdir(folder)
            try:
                found = [str(path) for path in pins.files(Path("."), "*.txt")]
            finally:
                os.chdir(here)
        self.assertEqual([Path(path).as_posix() for path in found], ["backend/requirements.txt"])


if __name__ == "__main__":
    unittest.main()
