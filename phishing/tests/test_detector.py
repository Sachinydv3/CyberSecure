from django.test import TestCase
from phishing.detector import detector

class PhishingDetectorTests(TestCase):
    def test_phishing_prediction(self):
        text = "URGENT: Your account is locked. Click here to verify your identity immediately: http://secure-verify-account.com"
        result = detector.predict(text)
        self.assertEqual(result, "Phishing")

    def test_safe_prediction(self):
        text = "Hi team, please find the meeting notes from yesterday attached to this email."
        result = detector.predict(text)
        self.assertEqual(result, "Safe")

    def test_metrics_loaded(self):
        metrics = detector.get_metrics()
        self.assertIn("accuracy", metrics)
        self.assertIn("confusion_matrix", metrics)
