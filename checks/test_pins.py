"""Tests for the pin check (checks/pins.py). No network.

    python -m unittest discover -s checks -p "test_*.py" -v

Each test gives the check some file text and checks what it reports. The
cases are the ones the phase 5 reviews reproduced as passing unnoticed.
"""

import unittest

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

    def test_local_actions_and_expressions_are_left_alone(self):
        text = "steps:\n  - uses: ./.github/actions/setup\n    container: ${{ matrix.image }}\n"
        self.assertEqual(pins.workflow_problems(".github/workflows/ci.yml", text), [])


class Dockerfiles(unittest.TestCase):
    def test_a_base_image_without_a_digest_fails(self):
        self.assertIn("python:3.12", " ".join(pins.dockerfile_problems("Dockerfile", "FROM --platform=linux/amd64 python:3.12\n")))

    def test_digests_scratch_and_earlier_stages_pass(self):
        text = f"FROM python:3.12@{DIGEST} AS build\nFROM scratch\nFROM build\nCOPY --from=build /a /a\n"
        self.assertEqual(pins.dockerfile_problems("Dockerfile", text), [])


class PreCommit(unittest.TestCase):
    def test_a_hook_pinned_by_tag_fails(self):
        text = "repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.30.1\n"
        self.assertIn("v8.30.1", " ".join(pins.precommit_problems(".pre-commit-config.yaml", text)))

    def test_a_frozen_hook_and_local_hooks_pass(self):
        text = f"repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: {SHA}  # frozen: v8.30.1\n  - repo: local\n    hooks: []\n"
        self.assertEqual(pins.precommit_problems(".pre-commit-config.yaml", text), [])


if __name__ == "__main__":
    unittest.main()
