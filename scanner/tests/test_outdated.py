"""Tests for scanner.outdated — version fingerprint table."""

from django.test import SimpleTestCase

from scanner import outdated


class OutdatedMatchTests(SimpleTestCase):
    def test_flags_old_apache(self):
        matches = outdated.match_version("Apache/2.2.15 (CentOS)")
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertEqual(m["product"], "Apache HTTP Server")
        self.assertEqual(m["observed"], "2.2.15")

    def test_flags_old_php(self):
        matches = outdated.match_version("PHP/7.4.33")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["product"], "PHP")

    def test_does_not_flag_current_apache(self):
        # 2.4.60 is the cutoff — anything ≥ is fine.
        self.assertEqual(outdated.match_version("Apache/2.4.60"), [])

    def test_does_not_flag_current_nginx(self):
        self.assertEqual(outdated.match_version("nginx/1.25.4"), [])

    def test_empty_input(self):
        self.assertEqual(outdated.match_version(""), [])

    def test_unknown_product_ignored(self):
        # Gunicorn isn't in our table — no matches.
        self.assertEqual(outdated.match_version("gunicorn/21.2.0"), [])

    def test_handle_release_letter(self):
        # OpenSSL 1.0.1u → parses to (1, 0, 1), which is < 3.2.0.
        matches = outdated.match_version("OpenSSL/1.0.1u")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["observed"], "1.0.1")
