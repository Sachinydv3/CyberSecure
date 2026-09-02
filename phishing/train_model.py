import pandas as pd
import numpy as np
import joblib
import json
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

def train():
    # 1. Load Dataset
    try:
        df = pd.read_csv('phishing/dataset/phishing_emails.csv')
    except FileNotFoundError:
        print("Error: Dataset file not found.")
        return

    X = df['text']
    y = df['label']

    # 2. Preprocessing
    # Use TF-IDF to convert text to numerical features
    # stop_words='english' removes common words that don't add value
    # ngram_range=(1, 2) captures both single words and pairs of words
    vectorizer = TfidfVectorizer(stop_words='english', ngram_range=(1, 2))
    X_tfidf = vectorizer.fit_transform(X)

    # 3. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X_tfidf, y, test_size=0.2, random_state=42, stratify=y)

    # 4. Train Model
    # RandomForest is robust and works well for text classification with TF-IDF
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred).tolist()

    print(f"Model Trained Successfully!")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Confusion Matrix: {conf_matrix}")

    # 6. Save Artifacts
    import os
    os.makedirs('phishing/ml_model', exist_ok=True)

    joblib.dump(vectorizer, 'phishing/ml_model/vectorizer.joblib')
    joblib.dump(model, 'phishing/ml_model/model.joblib')

    metrics = {
        "accuracy": accuracy,
        "confusion_matrix": conf_matrix
    }
    with open('phishing/ml_model/metrics.json', 'w') as f:
        json.dump(metrics, f)

    print("Artifacts saved to phishing/ml_model/")

if __name__ == "__main__":
    train()
