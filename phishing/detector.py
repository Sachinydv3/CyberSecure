import joblib
import json
import os
from django.conf import settings

class PhishingDetector:
    _instance = None
    _model = None
    _vectorizer = None
    _metrics = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PhishingDetector, cls).__new__(cls)
        return cls._instance

    def _load_artifacts(self):
        if self._model is None:
            # Paths to artifacts
            base_path = os.path.join(settings.BASE_DIR, 'phishing', 'ml_model')

            self._vectorizer = joblib.load(os.path.join(base_path, 'vectorizer.joblib'))
            self._model = joblib.load(os.path.join(base_path, 'model.joblib'))

            with open(os.path.join(base_path, 'metrics.json'), 'r') as f:
                self._metrics = json.load(f)

    def predict(self, text):
        self._load_artifacts()
        # Transform input text using the loaded vectorizer
        tfidf_text = self._vectorizer.transform([text])
        # Predict using the model
        prediction = self._model.predict(tfidf_text)[0]
        # Label is 1 for phishing, 0 for safe
        return "Phishing" if prediction == 1 else "Safe"

    def get_metrics(self):
        self._load_artifacts()
        return self._metrics

detector = PhishingDetector()
