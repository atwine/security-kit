"""Tests for the monthly watcher: planted changes, a quiet month, a second run.

The fake sources are built from the kit's real scanner pins, so the tests
stay right after a scanner update. They use no network.

    python -m unittest discover -s watch -v
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import watch  # noqa: E402

TODAY = dt.date(2026, 12, 1)
WINDOW = 45
REPO = "atwine/security-kit"
SOURCES = json.loads(watch.SOURCES.read_text(encoding="utf-8"))


def real_pins() -> dict[str, str]:
    return {
        name: re.findall(spec["pin"], (watch.ROOT / spec["file"]).read_text(encoding="utf-8"))[0]
        for name, spec in SOURCES["scanners"].items()
    }


def newer(version: str) -> str:
    major, minor, *_ = version.split(".")
    return f"{major}.{int(minor) + 1}.0"


def release(tag: str, published: str, draft: bool = False, prerelease: bool = False) -> dict:
    return {"tag_name": tag, "published_at": f"{published}T00:00:00Z", "draft": draft, "prerelease": prerelease}


class World:
    """The four sources as the watcher sees them, with or without one planted change each."""

    def __init__(self, planted: bool, issues: list | None = None):
        self.planted = planted
        self.issues = issues or []
        pins = real_pins()
        self.latest = {
            spec["repo"]: newer(pins[name]) if planted else pins[name]
            for name, spec in SOURCES["scanners"].items()
        }

    def get(self, url: str):
        if url == watch.KEV_URL:
            return self.kev(), None
        parsed = urllib.parse.urlparse(url)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        if path == "/advisories":
            return self.advisories(query), None
        if path.endswith("/releases/latest"):
            return {"tag_name": "v" + self.latest[path[len("/repos/"):-len("/releases/latest")]]}, None
        if path == "/repos/OWASP/ASVS/releases":
            # ASVS rebuilds a release called "latest" from work in progress; it is never an edition.
            return self.releases("v5.0.0_release", "v5.1.0_release", "v6.0.0_release", "latest"), None
        if path == "/repos/OWASP/www-project-top-10-for-large-language-model-applications/releases":
            return self.releases("2024", "2026", "2030"), None
        if path == "/repos/OWASP/Top10/contents":
            return self.folders("OWASP/Top10", "", ["2021", "2025"], "2029"), None
        if path == "/repos/OWASP/API-Security/contents/editions":
            return self.folders("OWASP/API-Security", "editions/", ["2019", "2023"], "2027"), None
        if path == f"/repos/{REPO}/issues":
            return self.issues, None
        raise AssertionError(f"unexpected address {url}")

    def releases(self, known: str, planted: str, unfinished: str, rolling: str | None = None) -> list:
        found = [
            release(known, "2025-05-30"),
            release(unfinished, "2026-11-29", draft=True),
            release(unfinished, "2026-11-30", prerelease=True),
        ]
        if rolling:
            found.append(release(rolling, "2026-11-30"))
        if self.planted:
            found.append(release(planted, "2026-11-20"))
        return found

    def folders(self, repo: str, prefix: str, known: list[str], planted: str) -> list:
        names = [*known, "scripts", "2021-2003_Comparison"] + ([planted] if self.planted else [])
        listing = [
            {"name": name, "type": "dir", "html_url": f"https://github.com/{repo}/tree/master/{prefix}{name}"}
            for name in names
        ]
        return listing + [{"name": "2031", "type": "file", "html_url": f"https://github.com/{repo}/blob/master/2031"}]

    def advisories(self, query: dict) -> list:
        assert query["type"] == ["reviewed"] and query["severity"] == ["critical"], query
        assert query["published"] == [f"{TODAY - dt.timedelta(days=WINDOW)}..{TODAY}"], query
        assert query["affects"] == [",".join(SOURCES["advisories"]["packages"][query["ecosystem"][0]])], query
        if not self.planted or query["ecosystem"] != ["npm"]:
            return []
        return [{
            "ghsa_id": "GHSA-2222-3333-4444",
            "summary": "Authorization bypass in middleware.",
            "published_at": "2026-11-20T10:00:00Z",
            "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "next"}}],
        }]

    def kev(self) -> dict:
        entries = [
            {"cveID": "CVE-2026-1000", "vendorProject": "Microsoft", "product": "Windows",
             "vulnerabilityName": "Not in the tracked stacks", "dateAdded": "2026-11-25"},
            {"cveID": "CVE-2026-1001", "vendorProject": "VMware", "product": "Reactor Netty",
             "vulnerabilityName": "Looks like React, isn't", "dateAdded": "2026-11-25"},
            {"cveID": "CVE-2025-1002", "vendorProject": "Kludex", "product": "Starlette",
             "vulnerabilityName": "Tracked, but older than the window", "dateAdded": "2026-01-10"},
        ]
        if self.planted:
            entries.append({"cveID": "CVE-2026-1003", "vendorProject": "PostgreSQL", "product": "PostgreSQL",
                            "vulnerabilityName": "SQL injection.", "dateAdded": "2026-11-28"})
        return {"catalogVersion": "test", "vulnerabilities": entries}


def planted_keys() -> set[str]:
    return {f"scanner:{name}:{newer(pin)}" for name, pin in real_pins().items()} | {
        "owasp:asvs:v5.1.0_release",
        "owasp:llm_top10:2026",
        "owasp:top10:2029",
        "owasp:api_top10:2027",
        "advisory:GHSA-2222-3333-4444",
        "exploited:CVE-2026-1003",
    }


class FakeResponse:
    def __init__(self, body: bytes, link: str = ""):
        self.body, self.headers = body, {"Link": link}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self.body


class WatcherTest(unittest.TestCase):
    def collect(self, world: World, sources: dict = SOURCES):
        return watch.collect(world.get, sources, watch.ROOT, TODAY, WINDOW)

    def run_watcher(self, world: World, dry_run: bool = False):
        posted, said = [], []

        def post(url: str, payload: dict) -> dict:
            posted.append(payload)
            return {"html_url": f"https://github.com/{REPO}/issues/1"}

        watch.run(world.get, post, REPO, watch.ROOT, SOURCES, TODAY, WINDOW, dry_run, said.append)
        return posted, said

    def test_a_quiet_month_proposes_nothing(self):
        items, notes = self.collect(World(planted=False))
        self.assertEqual(items, [])
        self.assertEqual(len(notes), 4)

    def test_each_planted_change_is_reported_with_a_source_link(self):
        items, _ = self.collect(World(planted=True))
        self.assertEqual({item.key for item in items}, planted_keys())
        for item in items:
            self.assertTrue(item.links, item.key)
            for link in item.links:
                self.assertTrue(link.startswith("https://"), link)

    def test_a_quiet_run_opens_no_issue(self):
        posted, said = self.run_watcher(World(planted=False))
        self.assertEqual(posted, [])
        self.assertIn("Nothing changed", said[-1])

    def test_a_second_run_proposes_nothing_new(self):
        posted, _ = self.run_watcher(World(planted=True))
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0]["labels"], ["kit-update"])
        again, said = self.run_watcher(World(planted=True, issues=[{"number": 1, "body": posted[0]["body"]}]))
        self.assertEqual(again, [])
        self.assertIn("Nothing new to propose", said[-1])

    def test_a_marker_in_a_pull_request_is_not_a_report(self):
        posted, _ = self.run_watcher(World(planted=True))
        pull = {"number": 2, "body": posted[0]["body"], "pull_request": {}}
        again, _ = self.run_watcher(World(planted=True, issues=[pull]))
        self.assertEqual(len(again), 1)

    def test_a_dry_run_opens_no_issue(self):
        posted, said = self.run_watcher(World(planted=True), dry_run=True)
        self.assertEqual(posted, [])
        self.assertIn("Would open: Kit update: 10 changes to review (2026-12)", said[-1])

    def test_the_issue_lists_items_as_checkboxes_with_a_hidden_record(self):
        items, _ = self.collect(World(planted=True))
        title, body = watch.render(items, TODAY)
        self.assertEqual(title, "Kit update: 10 changes to review (2026-12)")
        self.assertEqual(body.count("\n- [ ] "), 10)
        self.assertEqual(watch.MARKER.search(body).group(1).split(), sorted(planted_keys()))
        self.assertNotIn("..", body.replace("...", ""))

    def test_a_source_that_cannot_be_read_fails_the_run(self):
        world = World(planted=False)

        def broken(url: str):
            if url == watch.KEV_URL:
                raise watch.SourceError("network down")
            return world.get(url)

        with self.assertRaises(watch.SourceError):
            watch.collect(broken, SOURCES, watch.ROOT, TODAY, WINDOW)

    def test_a_pin_the_watcher_cannot_find_fails_the_run(self):
        sources = json.loads(json.dumps(SOURCES))
        sources["scanners"]["zap"]["pin"] = r"zaproxy-renamed:(\d+\.\d+\.\d+)"
        with self.assertRaises(watch.SourceError):
            self.collect(World(planted=False), sources)

    def test_outside_text_cannot_mention_link_or_add_markup(self):
        text = watch.clean("Bypass @octocat <script>alert(1)</script> [click](https://evil.example) `rm` #12 | ok")
        for bad in ("@", "<", ">", "[", "]", "(", ")", "`", "#", "|", "://", "evil"):
            self.assertNotIn(bad, text)
        self.assertTrue(text.startswith("Bypass octocat"), text)

    def test_the_github_token_goes_only_to_the_github_api(self):
        sent = {}

        def opener_open(request, timeout):
            sent[request.full_url] = request.get_header("Authorization")
            return FakeResponse(b"{}")

        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "placeholder"}), \
                mock.patch.object(watch.OPENER, "open", opener_open):
            watch.http_get(watch.KEV_URL)
            watch.http_get(f"{watch.API}/repos/OWASP/ASVS/releases")
        self.assertIsNone(sent[watch.KEV_URL])
        self.assertEqual(sent[f"{watch.API}/repos/OWASP/ASVS/releases"], "Bearer placeholder")

    def test_only_github_api_pages_are_followed(self):
        def opener_open(request, timeout):
            return FakeResponse(b"[]", '<https://elsewhere.example/page2>; rel="next"')

        with mock.patch.object(watch.OPENER, "open", opener_open):
            _, following = watch.http_get(f"{watch.API}/advisories")
        self.assertIsNone(following)

    def test_the_watcher_reads_only_https_from_two_github_hosts(self):
        def opener_open(request, timeout):
            raise AssertionError(f"opened {request.full_url}")

        with mock.patch.object(watch.OPENER, "open", opener_open):
            for address in ("file:///etc/passwd", "http://api.github.com/x", "ftp://api.github.com/x",
                            "https://elsewhere.example/x", "https://api.github.com.elsewhere.example/x"):
                with self.assertRaises(watch.SourceError, msg=address):
                    watch.http_get(address)

    def test_the_opener_follows_no_redirect_and_reads_no_files(self):
        kinds = {type(handler) for handler in watch.OPENER.handlers}
        self.assertIn(urllib.request.HTTPSHandler, kinds)
        for unsafe in (urllib.request.HTTPRedirectHandler, urllib.request.HTTPHandler, urllib.request.FileHandler,
                       urllib.request.FTPHandler, urllib.request.DataHandler, urllib.request.UnknownHandler):
            self.assertNotIn(unsafe, kinds)


if __name__ == "__main__":
    unittest.main()
