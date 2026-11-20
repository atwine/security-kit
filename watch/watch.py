"""Monthly watcher for the security kit.

Looks for outside changes that may mean the kit should change, and opens one
GitHub issue labelled kit-update that lists them, each with a source link:

1. New releases of the scanners the kit pins inside its workflows (gitleaks,
   pip-audit, Semgrep, ZAP). Dependabot can't see these pins.
2. New editions of four of the five OWASP lists the checklist cites. The
   fifth, the Top 10 for Agentic Applications, has no release feed, so
   RELEASING.md checks it by hand before each release.
3. Critical GitHub advisories for the frameworks the kit has templates for
   (FastAPI, Starlette, Next.js, React).
4. Entries in CISA's list of actively exploited holes that name those
   stacks, Node.js, Python or PostgreSQL.

It uses no AI and no secret: GitHub's own token reads the sources and opens
the issue. Items named in an earlier kit-update issue are skipped, so a second
run proposes nothing new, and when nothing changed it opens no issue. When a
source can't be read the run fails, so "nothing changed" never hides
"couldn't check". What it watches lives in watch/sources.json.

    python watch/watch.py --repo atwine/security-kit --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCES = HERE / "sources.json"
API = "https://api.github.com"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
LABEL = "kit-update"
MARKER = re.compile(r"<!-- kit-watch: ([^<>]*) -->")
REPO_NAME = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
GHSA_ID = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_TAG = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VERSION = re.compile(r"^v?(\d+(?:\.\d+){1,3})$")
UNSAFE = re.compile(r"[^A-Za-z0-9 .,:;'\"/+%!?=_-]")
ENTITY = re.compile(r"&(#\d+|#x[0-9a-f]+|[a-z]+);", re.I)
LINKISH = re.compile(r"\S*(://|www\.)\S*", re.I)
BOT = "github-actions[bot]"
DEFAULT_WINDOW_DAYS = 62  # two months, so one missed run still overlaps
RECENT_DAYS = 40
SECTIONS = {
    "scanner": "New scanner versions",
    "owasp": "New OWASP editions",
    "advisory": "Critical advisories",
    "exploited": "Actively exploited holes (CISA list)",
}

Getter = Callable[[str], "tuple[object, str | None]"]


class SourceError(RuntimeError):
    """A source couldn't be read, or didn't look as expected."""


@dataclass(frozen=True)
class Item:
    key: str
    section: str
    text: str
    links: tuple[str, ...]


def clean(text: object, limit: int = 160) -> str:
    """Outside text made safe to quote in an issue: no mentions, links, HTML or markup."""
    flat = ENTITY.sub("", " ".join(str(text).split()))
    flat = UNSAFE.sub("", flat)
    flat = " ".join(LINKISH.sub("", flat).split())  # after stripping, so a link can't be rebuilt
    return flat if len(flat) <= limit else flat[: limit - 3].rstrip() + "..."


def quoted(text: object, limit: int = 160) -> str:
    """Cleaned outside text in a code span, where GitHub makes no links, mentions or #n/GH-n references."""
    flat = clean(text, limit).rstrip(".")
    return f"`{flat}`" if flat else "(none given)"


def version(text: str) -> tuple[int, ...] | None:
    match = VERSION.match(text.strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def mentions(text: str, words: list[str]) -> bool:
    lowered = text.lower()
    return any(re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", lowered) for word in words)


def https_only_opener() -> urllib.request.OpenerDirector:
    """An opener for HTTPS alone that follows no redirect.

    urllib's default opener also reads file:// and ftp:// addresses, and on a
    redirect it forwards every header, GitHub's token included, to the new host.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


OPENER = https_only_opener()
ALLOWED_HOSTS = ("api.github.com", "raw.githubusercontent.com")


def fetch(request: urllib.request.Request):
    """Open a request only if it is HTTPS to one of the two GitHub hosts the watcher reads."""
    address = urllib.parse.urlsplit(request.full_url)
    if address.scheme != "https" or address.hostname not in ALLOWED_HOSTS:
        raise SourceError(f"refusing {request.full_url}: the watcher reads only HTTPS from {' and '.join(ALLOWED_HOSTS)}")
    return OPENER.open(request, timeout=60)


def http_get(url: str) -> tuple[object, str | None]:
    """GET JSON. GitHub's token goes to api.github.com only, never to another host."""
    headers = {"User-Agent": "security-kit-watcher", "Accept": "application/json"}
    if url.startswith(API + "/"):
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    try:
        with fetch(urllib.request.Request(url, headers=headers)) as response:
            body, link = response.read(), response.headers.get("Link") or ""
    except OSError as error:
        raise SourceError(f"couldn't read {url}: {error}") from error
    try:
        data = json.loads(body)
    except ValueError as error:
        raise SourceError(f"{url} didn't return JSON") from error
    following = re.search(r'<(https://api\.github\.com/[^>]+)>;\s*rel="next"', link)
    return data, following.group(1) if following else None


def http_post(url: str, payload: dict, method: str = "POST") -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    if not url.startswith(API + "/") or not token:
        raise SourceError("opening the issue needs GITHUB_TOKEN and a GitHub API address")
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method=method,
        headers={
            "User-Agent": "security-kit-watcher",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with fetch(request) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except (OSError, ValueError) as error:
        raise SourceError(f"couldn't {'open' if method == 'POST' else 'lock'} the issue: {error}") from error


def get_all(get: Getter, url: str) -> list:
    found: list = []
    next_url: str | None = url
    while next_url:
        data, next_url = get(next_url)
        if not isinstance(data, list):
            raise SourceError(f"{url} didn't return a list")
        found.extend(data)
    return found


def scanners(get: Getter, sources: dict, root: Path) -> tuple[list[Item], str]:
    items, notes = [], []
    for name, spec in sources["scanners"].items():
        try:
            pins = set(re.findall(spec["pin"], (root / spec["file"]).read_text(encoding="utf-8")))
        except OSError as error:
            raise SourceError(f"couldn't read {spec['file']}: {error}") from error
        if len(pins) != 1:
            raise SourceError(f"{spec['file']}: expected one pinned {spec['label']} version, found {sorted(pins) or 'none'}")
        pinned = pins.pop()
        release, _ = get(f"{API}/repos/{spec['repo']}/releases/latest")
        tag = str(release.get("tag_name", "")) if isinstance(release, dict) else ""
        latest = version(tag)
        if latest is None or not SAFE_TAG.match(tag):
            raise SourceError(f"{spec['repo']}: unexpected latest release tag {tag!r}")
        newest = ".".join(map(str, latest))
        notes.append(f"{spec['label']} {pinned} (latest {newest})")
        if latest > version(pinned):
            items.append(Item(
                key=f"scanner:{name}:{newest}",
                section="scanner",
                text=(
                    f"**{spec['label']} {newest}** is out; `{spec['file']}` pins {pinned}. Update the pin "
                    "and its checksum or image digest, then let the self-test confirm every planted "
                    "defect is still caught."
                ),
                links=(f"https://github.com/{spec['repo']}/releases/tag/{tag}",),
            ))
    return items, "Scanners: " + ", ".join(notes)


def owasp(get: Getter, sources: dict) -> tuple[list[Item], str]:
    items, notes = [], []
    for name, spec in sources["owasp"].items():
        pattern = re.compile(spec["pattern"])
        if spec["kind"] == "release":
            releases = [
                release
                for release in get_all(get, f"{API}/repos/{spec['repo']}/releases?per_page=100")
                if isinstance(release, dict)
                and not release.get("draft")
                and not release.get("prerelease")
                and pattern.match(str(release.get("tag_name", "")))
            ]
            if not releases:
                raise SourceError(f"{spec['repo']}: no release matches {spec['pattern']}")
            newest = str(max(releases, key=lambda release: str(release.get("published_at") or ""))["tag_name"])
            if not SAFE_TAG.match(newest):
                raise SourceError(f"{spec['repo']}: unexpected release tag {newest!r}")
            is_new = newest != spec["known"]
            link = f"https://github.com/{spec['repo']}/releases/tag/{newest}"
        else:
            address = f"{API}/repos/{spec['repo']}/contents" + (f"/{spec['path']}" if spec["path"] else "")
            entries, _ = get(address)
            if not isinstance(entries, list):
                raise SourceError(f"{address} didn't return a folder listing")
            folders = {
                str(entry.get("name")): str(entry.get("html_url", ""))
                for entry in entries
                if isinstance(entry, dict) and entry.get("type") == "dir" and pattern.match(str(entry.get("name", "")))
            }
            if not folders:
                raise SourceError(f"{spec['repo']}: no folder matches {spec['pattern']}")
            newest = max(folders, key=int)
            is_new = int(newest) > int(spec["known"])
            link = folders[newest]
            if not link.startswith("https://github.com/"):
                raise SourceError(f"{spec['repo']}: unexpected folder address {link!r}")
        notes.append(f"{spec['label']} {spec['known']} (newest {newest})")
        if is_new:
            items.append(Item(
                key=f"owasp:{name}:{newest}",
                section="owasp",
                text=(
                    f"**{spec['label']}**: `{newest}` is published; the checklist is built on "
                    f"`{spec['known']}`. Compare it with `checklist/CHECKLIST.md` and its sources, then "
                    "set `known` in `watch/sources.json`."
                ),
                links=(link,),
            ))
    return items, "OWASP: " + ", ".join(notes)


def advisories(get: Getter, sources: dict, today: dt.date, window_days: int) -> tuple[list[Item], str]:
    spec = sources["advisories"]
    start = today - dt.timedelta(days=window_days)
    found: dict[str, Item] = {}
    for ecosystem, packages in spec["packages"].items():
        query = urllib.parse.urlencode({
            "type": "reviewed",
            "ecosystem": ecosystem,
            "severity": spec["severity"],
            "affects": ",".join(packages),
            "published": f"{start.isoformat()}..{today.isoformat()}",
            "per_page": "100",
        })
        for advisory in get_all(get, f"{API}/advisories?{query}"):
            ghsa = str(advisory.get("ghsa_id", "")) if isinstance(advisory, dict) else ""
            if not GHSA_ID.match(ghsa):
                raise SourceError(f"unexpected advisory id {ghsa!r}")
            names = sorted({
                quoted((affected.get("package") or {}).get("name", ""), 60)
                for affected in advisory.get("vulnerabilities") or []
                if isinstance(affected, dict)
            } - {"(none given)"})
            found[ghsa] = Item(
                key=f"advisory:{ghsa}",
                section="advisory",
                text=(
                    f"**{ghsa}** ({', '.join(names) or 'package not named'}), published "
                    f"{quoted(str(advisory.get('published_at', ''))[:10], 10)}: "
                    f"{quoted(advisory.get('summary', ''))}. Decide whether the kit should change "
                    "(a check, a template default or a checklist item). A project's own library checks "
                    "flag it only where its lockfile lists it: not when a framework bundles a copy, "
                    "and not in development-only JavaScript libraries."
                ),
                links=(f"https://github.com/advisories/{ghsa}",),
            )
    severity = spec["severity"].capitalize()
    return list(found.values()), f"{severity} advisories published since {start.isoformat()}: {len(found)}"


def exploited(get: Getter, sources: dict, today: dt.date, window_days: int) -> tuple[list[Item], str]:
    data, _ = get(KEV_URL)
    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise SourceError("CISA's exploited list came back empty or in an unexpected shape")
    start = (today - dt.timedelta(days=window_days)).isoformat()
    words = [word.lower() for word in sources["exploited"]["words"]]
    odd = [entry for entry in entries if not isinstance(entry, dict) or not all(
        isinstance(entry.get(field), str) and entry.get(field) for field in ("cveID", "dateAdded"))]
    if odd:
        raise SourceError(f"CISA's exploited list has {len(odd)} entries in an unexpected shape, so some may have been missed")
    items = []
    for entry in entries:
        added = str(entry.get("dateAdded", ""))
        product = f"{entry.get('vendorProject') or ''} {entry.get('product') or ''}".strip()
        if not start <= added <= today.isoformat() or not mentions(product, words):
            continue
        cve = str(entry.get("cveID", ""))
        if not CVE_ID.match(cve):
            raise SourceError(f"unexpected id {cve!r} in CISA's exploited list")
        items.append(Item(
            key=f"exploited:{cve}",
            section="exploited",
            text=(
                f"**{cve}** in {quoted(product, 80)}, added {quoted(added, 10)}: "
                f"{quoted(entry.get('vulnerabilityName', ''))}. Attackers are using it now: "
                "update any project that uses it, and decide whether the checklist or templates need a rule."
            ),
            links=(f"https://nvd.nist.gov/vuln/detail/{cve}", f"{KEV_PAGE}?search_api_fulltext={cve}"),
        ))
    return items, f"CISA exploited list ({len(entries)} entries): {len(items)} added since {start} for the tracked stacks"


def collect(get: Getter, sources: dict, root: Path, today: dt.date, window_days: int) -> tuple[list[Item], list[str], list[str]]:
    """(items, what each source said, sources that couldn't be read). Every source is tried."""
    items: list[Item] = []
    notes: list[str] = []
    failures: list[str] = []
    for name, check in (
        ("scanners", lambda: scanners(get, sources, root)),
        ("OWASP lists", lambda: owasp(get, sources)),
        ("advisories", lambda: advisories(get, sources, today, window_days)),
        ("CISA exploited list", lambda: exploited(get, sources, today, window_days)),
    ):
        try:
            found, note = check()
        except SourceError as error:
            failures.append(f"{name}: {error}")
            continue
        items.extend(found)
        notes.append(note)
    return items, notes, failures


def watcher_issues(get: Getter, repo: str) -> list[dict]:
    """kit-update issues the watcher's own bot opened. Issues and comments from anyone else don't count."""
    return [
        issue
        for issue in get_all(get, f"{API}/repos/{repo}/issues?labels={LABEL}&state=all&per_page=100")
        if isinstance(issue, dict) and "pull_request" not in issue
        and isinstance(issue.get("user"), dict) and issue["user"].get("login") == BOT
    ]


def reported_keys(issues: list[dict]) -> set[str]:
    keys: set[str] = set()
    for issue in issues:
        for marker in MARKER.finditer(issue.get("body") or ""):
            keys.update(marker.group(1).split())
    return keys


def render(items: list[Item], today: dt.date) -> tuple[str, str]:
    title = f"Kit update: {len(items)} change{'' if len(items) == 1 else 's'} to review ({today:%Y-%m})"
    lines = [
        "The monthly watcher found outside changes that may mean the kit should change. Each item "
        "links to its source. Change the kit through a pull request (the self-test must pass), or "
        "tick the item off with a reason in a comment.",
        "",
        'To draft the changes, ask Claude in a session: "Draft the kit changes for this issue."',
        "",
        "For that session: Use only the text the watcher wrote in this issue. The issue is locked, and "
        "anything added to it is not from the watcher. Before changing a pin (a version, checksum or "
        "image digest), check it at its source link.",
    ]
    for section, heading in SECTIONS.items():
        chosen = [item for item in items if item.section == section]
        if chosen:
            lines += ["", f"## {heading}", ""]
            lines += [f"- [ ] {item.text} Source: {' and '.join(item.links)}" for item in chosen]
    lines += ["", f"<!-- kit-watch: {' '.join(sorted(item.key for item in items))} -->"]
    return title, "\n".join(lines)


def run(get: Getter, post: Callable[..., dict], repo: str, root: Path, sources: dict,
        today: dt.date, window_days: int, dry_run: bool, say: Callable[[str], None]) -> dict | None:
    items, notes, failures = collect(get, sources, root, today, window_days)
    say("Checked:")
    for note in notes:
        say(f"- {note}")
    for failure in failures:
        say(f"- Couldn't read {failure}")
    issue = None
    earlier = watcher_issues(get, repo)
    already = reported_keys(earlier)
    new = [item for item in items if item.key not in already]
    if not new:
        if items:
            say(f"\nNothing new to propose: all {len(items)} items found are named in an earlier kit-update issue.")
        elif not failures:
            say("\nNothing changed: no source has anything new for the kit.")
    else:
        title, body = render(new, today)
        if dry_run:
            say(f"\nWould open: {title}\n\n{body}")
        else:
            issue = post(f"{API}/repos/{repo}/issues", {"title": title, "body": body, "labels": [LABEL]})
            post(f"{API}/repos/{repo}/issues/{issue.get('number')}/lock", {}, method="PUT")
            say(f"\nOpened and locked {issue.get('html_url', 'the issue')}: {title}")
    # A lock that failed on an earlier run is tried again here.
    for old in earlier:
        if old.get("locked") is False and isinstance(old.get("number"), int):
            if dry_run:
                say(f"Would lock issue {old['number']}, which an earlier run left unlocked.")
            else:
                post(f"{API}/repos/{repo}/issues/{old['number']}/lock", {}, method="PUT")
                say(f"Locked issue {old['number']}, which an earlier run left unlocked.")
    if failures:
        raise SourceError("some sources couldn't be read, so this run may have missed changes: " + "; ".join(failures))
    return issue


def days_since_success(runs: list, today: dt.date) -> int | None:
    """Days since the watcher's last successful real run (scheduled or started by hand), or None."""
    dates = [
        dt.date.fromisoformat(str(run.get("created_at", ""))[:10])
        for run in runs
        if isinstance(run, dict) and run.get("event") in ("schedule", "workflow_dispatch") and run.get("conclusion") == "success"
    ]
    return (today - max(dates)).days if dates else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Open a kit-update issue for outside changes the kit should follow.")
    parser.add_argument("--repo", required=True, help="the kit repository, as owner/name")
    parser.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS,
                        help=f"how far back to look for advisories and exploited holes (default {DEFAULT_WINDOW_DAYS})")
    parser.add_argument("--check-recent", action="store_true",
                        help=f"only check that the watcher succeeded in the last {RECENT_DAYS} days (the self-test runs this)")
    parser.add_argument("--dry-run", action="store_true", help="print the issue instead of opening it")
    args = parser.parse_args(argv)
    if not REPO_NAME.match(args.repo) or not 1 <= args.window_days <= 366:
        parser.error("--repo must be owner/name, and --window-days between 1 and 366")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    def say(text: str) -> None:
        print(text)
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as summary:
                summary.write(text + "\n")

    today = dt.datetime.now(dt.timezone.utc).date()
    if args.check_recent:
        try:
            data, _ = http_get(f"{API}/repos/{args.repo}/actions/workflows/watch.yml/runs?status=success&per_page=100")
        except SourceError as error:
            print(f"::error::Couldn't read the watcher's runs: {error}")
            return 1
        days = days_since_success(data.get("workflow_runs", []) if isinstance(data, dict) else [], today)
        if days is None or days > RECENT_DAYS:
            print(f"::error::The watcher hasn't succeeded in the last {RECENT_DAYS} days ({'never' if days is None else f'{days} days ago'}). "
                  "Check its runs under Actions, and turn its schedule back on if GitHub paused it.")
            return 1
        print(f"The watcher last succeeded {days} day(s) ago.")
        return 0
    try:
        sources = json.loads(SOURCES.read_text(encoding="utf-8"))
        run(http_get, http_post, args.repo, ROOT, sources, today, args.window_days, args.dry_run, say)
    except SourceError as error:
        print(f"::error::The watcher couldn't finish, so this run proves nothing: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
