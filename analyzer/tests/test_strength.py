"""Tests for the strength scoring engine."""

from django.test import SimpleTestCase

from analyzer import strength


class StrengthEngineTests(SimpleTestCase):
    def test_empty_password_is_weak(self):
        r = strength.evaluate("")
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["label"], "weak")
        self.assertEqual(r["length"], 0)
        self.assertEqual(r["checks"], [])

    def test_short_password_is_weak(self):
        r = strength.evaluate("ab1!")
        self.assertLess(r["score"], 40)
        self.assertEqual(r["label"], "weak")

    def test_common_password_is_penalized(self):
        r = strength.evaluate("password")
        # 8 chars × medium length score, but a -35 common-password penalty
        # must drag it below the "medium" threshold.
        self.assertLess(r["score"], 40)
        self.assertEqual(r["label"], "weak")
        # Common-password check must fail.
        common_check = next(c for c in r["checks"] if "common" in c["label"].lower())
        self.assertFalse(common_check["passed"])

    def test_strong_password_passes(self):
        r = strength.evaluate("Sup3rStrong!Pass#42")
        self.assertGreaterEqual(r["score"], 80)
        self.assertEqual(r["label"], "very_strong")

    def test_repeat_characters_penalized(self):
        r = strength.evaluate("aaaaaaa")
        repeat_check = next(c for c in r["checks"] if "repeated" in c["label"].lower())
        self.assertFalse(repeat_check["passed"])

    def test_keyboard_row_penalized(self):
        r = strength.evaluate("Qwerty123!")
        kbd_check = next(c for c in r["checks"] if "keyboard" in c["label"].lower())
        self.assertFalse(kbd_check["passed"])

    def test_sequential_run_penalized(self):
        r = strength.evaluate("Abcdefgh1!")
        seq_check = next(c for c in r["checks"] if "sequential" in c["label"].lower())
        self.assertFalse(seq_check["passed"])

    def test_all_digits_penalized(self):
        r = strength.evaluate("12345678")
        # all-digits → no uppercase, no lowercase, no symbol.
        self.assertEqual(r["score"] < 40, True)
        self.assertEqual(r["label"], "weak")

    def test_passphrase_scores_well(self):
        r = strength.evaluate("correct horse battery staple")
        # Long + mixed case + space-separated, no symbols needed for strong.
        self.assertGreaterEqual(r["score"], 60)
        self.assertIn(r["label"], ("strong", "very_strong"))

    def test_score_is_capped_at_100(self):
        r = strength.evaluate("a" * 1000 + "B1!")
        self.assertLessEqual(r["score"], 100)

    def test_checks_count(self):
        r = strength.evaluate("anything")
        self.assertEqual(len(r["checks"]), 9)


class LabelThresholdTests(SimpleTestCase):
    def test_label_thresholds(self):
        # Construct passwords that should land in each band.
        cases = [
            ("12345678", "weak"),
            ("CorrectPass1", "medium"),  # borderline — length bonus only
            ("Sup3rStrong!Pass#42", "very_strong"),
        ]
        for pw, expected in cases:
            label = strength.evaluate(pw)["label"]
            self.assertEqual(
                label,
                expected,
                f"{pw!r} → {label}, expected {expected}",
            )
