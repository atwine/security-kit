"""The kit's own website check: the protections ZAP can't see over plain HTTP.

    python -I site_policy.py <start url> <rules file> <report.json>

Fetches the start page, the same-site pages it redirects to, and up to
MAX_PAGES - 1 pages it links to on the same site, checking every response
along the way (each redirect too), and reports by id:

    KIT-HSTS             no Strict-Transport-Security with a max-age above 0
    KIT-REFERRER         no Referrer-Policy
    KIT-PERMISSIONS      no Permissions-Policy
    KIT-COOKIE-SECURE    a cookie without Secure
    KIT-COOKIE-SAMESITE  a cookie without SameSite
    KIT-CORS             any site may read the response (Access-Control-Allow-Origin
                         is * or echoes a made-up origin)
    KIT-FETCH            a page couldn't be fetched, so it wasn't checked

A line "KIT-<id><tab>IGNORE<tab>(reason)" in the rules file accepts one,
the same way the file accepts a ZAP rule; the reason is required. Cookies set only after signing in
are not seen. Writes the findings that fail and the accepted ones to report.json, and
exits 1 when any fails. Standard library only.
"""

import json
import re
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

MAX_PAGES = 20
STRANGE_ORIGIN = "https://security-kit-check.invalid"
TIMEOUT = 15


def _values(headers, name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name.lower()]


def check_page(url: str, headers) -> list[str]:
    """Findings for one page's response headers, as 'KIT-ID url: what is wrong'."""
    found = []
    hsts = " ".join(_values(headers, "Strict-Transport-Security"))
    age = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
    if not age or int(age.group(1)) <= 0:
        found.append(f"KIT-HSTS {url}: no Strict-Transport-Security header with a max-age above 0")
    if not _values(headers, "Referrer-Policy"):
        found.append(f"KIT-REFERRER {url}: no Referrer-Policy header")
    if not _values(headers, "Permissions-Policy"):
        found.append(f"KIT-PERMISSIONS {url}: no Permissions-Policy header")
    for cookie in _values(headers, "Set-Cookie"):
        name = cookie.split("=", 1)[0].strip()
        attributes = [part.strip().lower() for part in cookie.split(";")[1:]]
        if any(re.fullmatch(r"max-age\s*=\s*0", part) for part in attributes):
            continue  # a cookie being deleted
        flags = {part.split("=", 1)[0].strip() for part in attributes}
        if "secure" not in flags:
            found.append(f"KIT-COOKIE-SECURE {url}: cookie '{name}' has no Secure flag")
        if "samesite" not in flags:
            found.append(f"KIT-COOKIE-SAMESITE {url}: cookie '{name}' has no SameSite attribute")
    return found


def check_cors(url: str, headers) -> list[str]:
    """Findings for a response to a request carrying a made-up Origin."""
    allowed = [value.strip() for value in _values(headers, "Access-Control-Allow-Origin")]
    if "*" in allowed or STRANGE_ORIGIN in allowed:
        return [f"KIT-CORS {url}: any site may read this response (Access-Control-Allow-Origin: {', '.join(allowed)})"]
    return []


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.found.append(href)


def same_site_links(base: str, html: str) -> list[str]:
    """Pages on the same site the start page links to, at most MAX_PAGES - 1."""
    parser = _Links()
    parser.feed(html)
    origin = urlsplit(base)[:2]
    pages = []
    for href in parser.found:
        page = urljoin(base, href).split("#", 1)[0]
        if urlsplit(page)[:2] == origin and page != base and page not in pages:
            pages.append(page)
    return pages[: MAX_PAGES - 1]


def accepted(rules: str) -> set[str]:
    """Kit check ids a rules file marks IGNORE, in its tab format with a reason: KIT-ID<tab>IGNORE<tab>(reason)."""
    ids = set()
    for line in rules.splitlines():
        parts = line.split("	")
        if len(parts) >= 3 and parts[0].startswith("KIT-") and parts[1] == "IGNORE" and re.fullmatch(r"\(.*\S.*\)", parts[2].strip()):
            ids.add(parts[0])
    return ids


def failing(findings: list[str], ok: set[str]) -> list[str]:
    return [item for item in findings if item.split()[0] not in ok]


MAX_HOPS = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url: str, origin: str | None = None):
    """(status, headers, body text) of one GET, not following redirects."""
    request = urllib.request.Request(url, headers={"Origin": origin} if origin else {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        response = opener.open(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as error:  # a 3xx, 4xx or 5xx still has headers to check
        response = error
    with response:
        body = response.read(2_000_000).decode("utf-8", "replace")
        return response.status, list(response.headers.items()), body


def _follow(url: str, get, origin: str | None = None):
    """Each hop of a page and its same-site redirects as (url, headers), and the last body."""
    hops, seen = [], set()
    while True:
        status, headers, body = get(url, origin)
        hops.append((url, headers))
        seen.add(url)
        location = _values(headers, "Location")
        if not (300 <= status < 400 and location) or len(hops) > MAX_HOPS:
            return hops, body
        target = urljoin(url, location[0]).split("#", 1)[0]
        if urlsplit(target)[:2] != urlsplit(url)[:2] or target in seen:
            return hops, body
        url = target


def crawl(start: str, get=fetch) -> list[str]:
    """Findings for the start page, the same-site pages it redirects to, and the pages it links to."""
    findings = []

    def visit(url: str) -> list[str]:
        try:
            hops, body = _follow(url, get)
            cross_site = _follow(url, get, STRANGE_ORIGIN)[0]
        except (OSError, ValueError) as error:  # URLError and timeouts are OSErrors
            findings.append(f"KIT-FETCH {url}: couldn't be fetched ({error})")
            return []
        for page, headers in hops:
            findings.extend(check_page(page, headers))
        for page, headers in cross_site:
            findings.extend(check_cors(page, headers))
        return same_site_links(hops[-1][0], body)

    for page in visit(start):
        visit(page)
    return findings


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: site_policy.py <start url> <rules file> <report.json>", file=sys.stderr)
        return 2
    start, rules_file, report = argv
    with open(rules_file, encoding="utf-8") as rules:
        ok = accepted(rules.read())
    findings = crawl(start)
    problems = failing(findings, ok)
    with open(report, "w", encoding="utf-8") as out:
        json.dump({"failing": problems, "accepted": [item for item in findings if item not in problems]}, out, indent=2)
    for item in findings:
        print(("" if item in problems else "accepted: ") + item)
    print(f"{len(problems)} problem(s)." if problems else "Nothing missing.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
