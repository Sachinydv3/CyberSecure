"""Tests for analyzer views — covers GET, AJAX endpoints, and form-submit
persistence behaviour."""

import json

from django.test import Client, TestCase
from django.urls import reverse

from analyzer.models import PasswordHistory


class AnalyzerViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_index_renders(self):
        res = self.client.get(reverse("analyzer:analyzer_index"))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Password Strength Analyzer")
        self.assertContains(res, 'id="password-input"')

    def test_learn_renders(self):
        res = self.client.get(reverse("analyzer:analyzer_learn"))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Password Security 101")

    def test_ajax_check_returns_json(self):
        res = self.client.post(
            reverse("analyzer:analyzer_ajax_check"),
            data=json.dumps({"password": "Sup3rStrong!Pass#42"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["label"], "very_strong")
        self.assertGreaterEqual(data["score"], 80)
        self.assertEqual(len(data["checks"]), 9)

    def test_ajax_check_requires_post(self):
        res = self.client.get(reverse("analyzer:analyzer_ajax_check"))
        self.assertEqual(res.status_code, 405)

    def test_ajax_check_rejects_invalid_json(self):
        res = self.client.post(
            reverse("analyzer:analyzer_ajax_check"),
            data="not json",
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)

    def test_ajax_check_rejects_oversized_input(self):
        res = self.client.post(
            reverse("analyzer:analyzer_ajax_check"),
            data=json.dumps({"password": "x" * 10_000}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)

    def test_ajax_suggest_returns_suggestions(self):
        res = self.client.post(
            reverse("analyzer:analyzer_ajax_suggest"),
            data=json.dumps({"base": "hello", "count": 3}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("suggestions", data)
        self.assertGreaterEqual(len(data["suggestions"]), 1)
        for s in data["suggestions"]:
            self.assertIn("value", s)
            self.assertIn("score", s)
            self.assertIn("label", s)

    def test_form_submit_persists_hash(self):
        pw = "Sup3rStrong!Pass#42"
        res = self.client.post(
            reverse("analyzer:analyzer_index"),
            data={"password": pw, "consent": "on"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(PasswordHistory.objects.count(), 1)
        row = PasswordHistory.objects.first()
        # Hash must be SHA-256 hex (64 chars), never the plaintext.
        self.assertEqual(len(row.password_hash), 64)
        self.assertNotEqual(row.password_hash, pw)

    def test_form_submit_dedupes_via_get_or_create(self):
        pw = "AnotherStrong#Pass99"
        for _ in range(3):
            self.client.post(
                reverse("analyzer:analyzer_index"),
                data={"password": pw, "consent": "on"},
            )
        self.assertEqual(
            PasswordHistory.objects.filter(password_hash=PasswordHistory.hash_password(pw)).count(),
            1,
        )

    def test_form_submit_without_consent_is_rejected(self):
        res = self.client.post(
            reverse("analyzer:analyzer_index"),
            data={"password": "anything", "consent": ""},
        )
        # Form invalid → re-render with errors, no row created.
        self.assertEqual(res.status_code, 200)
        self.assertEqual(PasswordHistory.objects.count(), 0)
