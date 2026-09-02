"""Tests for scanner.http_checks — header / cookie / exposure / outdated."""

from email.message import Message

from django.test import SimpleTestCase

from scanner import http_checks


def _msg(items):
    """Build an email.message.Message from a dict."""
    m = Message()
    for k, v in items.items():
        m[k] = v
    return m


def _no_op_fetch(status=200, headers=None):
    """A fake ``fetch`` callable that always returns the same response."""
    def _fetch(url):
        return status, headers or _msg({})
    return _fetch


class HeaderChecksTests(SimpleTestCase):
    def test_flags_missing_security_headers(self):
        findings = http_checks.check_headers(
            "https://example.com/", _msg({"Server": "nginx"})
        )
        titles = {f["title"] for f in findings}
        # HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy
        self.assertIn("Missing Strict-Transport-Security (HSTS)", titles)
        self.assertIn("Missing Content-Security-Policy (CSP)", titles)
        self.assertIn("Missing X-Content-Type-Options: nosniff", titles)

    def test_server_disclosure_flagged(self):
        findings = http_checks.check_headers(
            "https://example.com/",
            _msg({"Server": "Apache/2.2.15"}),
        )
        disclosure = [f for f in findings if "disclosed" in f["title"]]
        self.assertEqual(len(disclosure), 1)
        self.assertEqual(disclosure[0]["severity"], "medium")

    def test_clean_response_has_no_findings(self):
        headers = _msg({
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        })
        self.assertEqual(http_checks.check_headers("https://x/", headers), [])


class CookieChecksTests(SimpleTestCase):
    def test_flags_insecure_cookie_on_https(self):
        headers = _msg({
            "Set-Cookie": "session=abc; Path=/",
        })
        findings = http_checks.check_cookies("https://x/", headers)
        titles = {f["title"] for f in titles_severities(findings)}
        self.assertIn("Cookie 'session' missing Secure flag", titles)

    def test_no_findings_for_well_configured_cookie(self):
        headers = _msg({
            "Set-Cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        })
        self.assertEqual(http_checks.check_cookies("https://x/", headers), [])


def titles_severities(findings):
    return [{"title": f["title"], "severity": f["severity"]} for f in findings]


class ExposureChecksTests(SimpleTestCase):
    def test_probes_expected_paths(self):
        # Track which paths were probed by intercepting fetch.
        seen = []
        def fake_fetch(url):
            seen.append(url)
            if url.endswith("/.env"):
                return 200, _msg({})
            return 404, _msg({})
        findings = http_checks.check_exposure("https://x.example/", fake_fetch)
        # Many paths probed, only .env produced a finding.
        self.assertGreater(len(seen), 5)
        env_finding = next(f for f in findings if ".env" in f["title"])
        self.assertEqual(env_finding["severity"], "high")

    def test_handles_fetch_exception(self):
        def broken_fetch(url):
            raise OSError("network down")
        findings = http_checks.check_exposure("https://x/", broken_fetch)
        # No exception propagates; just no findings.
        self.assertEqual(findings, [])


class OutdatedSoftwareTests(SimpleTestCase):
    def test_flags_old_apache_via_server_header(self):
        headers = _msg({"Server": "Apache/2.2.15"})
        findings = http_checks.check_outdated_software(headers)
        self.assertEqual(len(findings), 1)
        self.assertIn("Apache", findings[0]["title"])


class UrlSafetyTests(SimpleTestCase):
    def test_accepts_http_and_https(self):
        self.assertTrue(http_checks.is_safe_url("http://example.com/"))
        self.assertTrue(http_checks.is_safe_url("https://example.com/path?q=1"))
        self.assertTrue(http_checks.is_safe_url("http://127.0.0.1:8000/"))

    def test_rejects_garbage(self):
        self.assertFalse(http_checks.is_safe_url(""))
        self.assertFalse(http_checks.is_safe_url("not a url"))
        self.assertFalse(http_checks.is_safe_url("ftp://example.com/"))
        self.assertFalse(http_checks.is_safe_url("javascript:alert(1)"))

    def test_rejects_overlong_url(self):
        self.assertFalse(http_checks.is_safe_url("http://x.example/" + "a" * 3000))


class OrchestratorTests(SimpleTestCase):
    def test_run_http_checks_aggregates(self):
        headers = _msg({"Server": "Apache/2.2.15"})
        # Run with no-op fetch so exposure check sees 200 on every path.
        findings = http_checks.run_http_checks(
            "http://127.0.0.1:8000/", headers, _no_op_fetch(200, headers)
        )
        # We should see at least: missing headers (6), outdated Apache,
        # plus exposed paths (each producing an info/high finding).
        self.assertGreater(len(findings), 5)
        categories = {f["category"] for f in findings}
        self.assertIn("http-headers", categories)
        self.assertIn("outdated", categories)
        self.assertIn("exposure", categories)
