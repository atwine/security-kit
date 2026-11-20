"""Tests for the kit's own website check (checks/site_policy.py). No network.

    python -m unittest discover -s checks -p "test_*.py" -v

Each test gives the check the response headers a page sent and checks what
it reports.
"""

import unittest

import site_policy

URL = "http://127.0.0.1:8000/"
GOOD = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Content-Type", "text/html"),
]


def without(*names):
    return [(name, value) for name, value in GOOD if name.lower() not in {n.lower() for n in names}]


class Page(unittest.TestCase):
    def test_a_page_with_every_header_passes(self):
        self.assertEqual(site_policy.check_page(URL, GOOD), [])

    def test_each_missing_header_is_reported_by_its_id(self):
        found = site_policy.check_page(URL, without("Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"))
        self.assertEqual([item.split()[0] for item in found], ["KIT-HSTS", "KIT-REFERRER", "KIT-PERMISSIONS"])
        self.assertIn(URL, found[0])

    def test_an_hsts_header_with_no_max_age_does_not_count(self):
        found = site_policy.check_page(URL, without("Strict-Transport-Security") + [("Strict-Transport-Security", "max-age=0")])
        self.assertEqual([item.split()[0] for item in found], ["KIT-HSTS"])

    def test_header_names_are_matched_whatever_their_case(self):
        self.assertEqual(site_policy.check_page(URL, [(name.upper(), value) for name, value in GOOD]), [])

    def test_a_cookie_needs_secure_and_samesite(self):
        found = site_policy.check_page(URL, GOOD + [("Set-Cookie", "session=x; HttpOnly; Path=/")])
        self.assertEqual([item.split()[0] for item in found], ["KIT-COOKIE-SECURE", "KIT-COOKIE-SAMESITE"])
        self.assertIn("session", found[0])

    def test_a_cookie_with_both_flags_passes(self):
        self.assertEqual(site_policy.check_page(URL, GOOD + [("Set-Cookie", "session=x; HttpOnly; Secure; SameSite=Lax; Path=/")]), [])

    def test_samesite_none_still_needs_secure(self):
        found = site_policy.check_page(URL, GOOD + [("Set-Cookie", "id=1; SameSite=None")])
        self.assertEqual([item.split()[0] for item in found], ["KIT-COOKIE-SECURE"])


class Cors(unittest.TestCase):
    def test_any_origin_is_reported(self):
        self.assertEqual([i.split()[0] for i in site_policy.check_cors(URL, [("Access-Control-Allow-Origin", "*")])], ["KIT-CORS"])

    def test_echoing_a_strange_origin_is_reported(self):
        headers = [("Access-Control-Allow-Origin", site_policy.STRANGE_ORIGIN)]
        self.assertEqual([i.split()[0] for i in site_policy.check_cors(URL, headers)], ["KIT-CORS"])

    def test_no_cross_site_access_passes(self):
        self.assertEqual(site_policy.check_cors(URL, []), [])

    def test_an_exact_trusted_origin_passes(self):
        self.assertEqual(site_policy.check_cors(URL, [("Access-Control-Allow-Origin", "https://app.example.org")]), [])


class Pages(unittest.TestCase):
    def test_same_site_links_are_followed_and_others_are_not(self):
        html = '<a href="/items/1">1</a><a href="https://elsewhere.example/">x</a><a href="about">a</a><a href="/items/1">again</a>'
        self.assertEqual(site_policy.same_site_links(URL, html), ["http://127.0.0.1:8000/items/1", "http://127.0.0.1:8000/about"])

    def test_links_are_capped(self):
        html = "".join(f'<a href="/p{n}">p</a>' for n in range(50))
        self.assertEqual(len(site_policy.same_site_links(URL, html)), site_policy.MAX_PAGES - 1)


class Crawl(unittest.TestCase):
    def fake(self, pages):
        """A fetch function serving pages: url -> (status, headers, body)."""

        def fetch(url, origin=None):
            if url not in pages:
                raise OSError("connection refused")
            return pages[url]

        return fetch

    def test_a_same_site_redirect_is_followed_and_every_hop_is_checked(self):
        pages = {
            URL: (307, GOOD + [("Location", "/welcome")], ""),
            URL + "welcome": (200, GOOD + [("Set-Cookie", "session=x; HttpOnly")], "<p>hi</p>"),
        }
        found = site_policy.crawl(URL, self.fake(pages))
        self.assertIn("KIT-COOKIE-SECURE " + URL + "welcome: cookie 'session' has no Secure flag", found)

    def test_a_redirect_to_another_site_is_not_followed(self):
        pages = {URL: (302, GOOD + [("Location", "https://login.example.org/")], "")}
        self.assertEqual(site_policy.crawl(URL, self.fake(pages)), [])

    def test_a_page_that_cannot_be_fetched_is_reported(self):
        pages = {URL: (200, GOOD, '<a href="/gone">x</a>')}
        found = site_policy.crawl(URL, self.fake(pages))
        self.assertEqual([item.split()[0] for item in found], ["KIT-FETCH"])
        self.assertIn(URL + "gone", found[0])

    def test_a_cookie_being_deleted_is_not_reported(self):
        self.assertEqual(site_policy.check_page(URL, GOOD + [("Set-Cookie", "session=; Max-Age=0; Path=/")]), [])


class Accepted(unittest.TestCase):
    def test_a_rules_file_can_accept_a_kit_check_with_a_reason(self):
        rules = "10038\tFAIL\t(CSP)\nKIT-HSTS\tIGNORE\t(our host adds HSTS on HTTPS only)\nKIT-CORS\tFAIL\t(keep)\n"
        self.assertEqual(site_policy.accepted(rules), {"KIT-HSTS"})

    def test_accepting_needs_the_tab_format_and_a_reason(self):
        rules = "KIT-HSTS IGNORE (spaces, not tabs)\nKIT-CORS\tIGNORE\n  KIT-REFERRER\tIGNORE\t(indented)\n"
        self.assertEqual(site_policy.accepted(rules), set())

    def test_accepted_findings_do_not_fail(self):
        findings = site_policy.check_page(URL, without("Strict-Transport-Security"))
        self.assertEqual(site_policy.failing(findings, {"KIT-HSTS"}), [])


if __name__ == "__main__":
    unittest.main()
