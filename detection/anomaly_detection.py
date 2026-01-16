import numpy as np
from collections import Counter
from datetime import datetime
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42
        )
        self.trained = False

    def extract_features(self, events):
        process_counts = Counter(e["process"] for e in events)
        total_events = len(events)

        features = []
        metadata = []

        for event in events:
            timestamp = datetime.fromisoformat(event["timestamp"])
            hour = timestamp.hour

            process = event["process"]

            feature_vector = [
                process_counts[process] / total_events,   # frequency
                1 if event["event_type"] == "SYSTEM_ERROR" else 0,
                hour / 23.0
            ]

            features.append(feature_vector)
            metadata.append(event)

        return np.array(features), metadata

    def train(self, events):
        X, _ = self.extract_features(events)
        self.model.fit(X)
        self.trained = True

    def detect(self, events):
        if not self.trained:
            raise RuntimeError("Model not trained")

        X, metadata = self.extract_features(events)
        scores = self.model.decision_function(X)
        predictions = self.model.predict(X)

        anomalies = []

        for i, pred in enumerate(predictions):
            if pred == -1:
                anomalies.append({
                    "event": metadata[i],
                    "anomaly_score": scores[i]
                })

        return anomalies
