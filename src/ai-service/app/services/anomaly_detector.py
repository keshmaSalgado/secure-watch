import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import uuid
from typing import List, Dict, Any

class AnomalyDetectionEngine:
    def __init__(self):
        # 5% expected contamination (outlier fraction)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self._train_baseline_model()

    def _train_baseline_model(self):
        """
        Trains Isolation Forest on synthetic baseline telemetry:
        Features:
        0: failed_login_count_1h (normal: 0-2)
        1: hour_deviation_from_workday (normal: 0-3 hours from 9am-6pm)
        2: targeted_accounts_count (normal: 1)
        3: ip_change_velocity (normal: 0-1)
        4: request_rate_per_min (normal: 5-30)
        """
        np.random.seed(42)
        n_samples = 1500

        # Normal telemetry distribution
        failed_logins = np.random.poisson(lam=0.5, size=n_samples)
        hour_deviations = np.random.exponential(scale=1.5, size=n_samples)
        targeted_accounts = np.ones(n_samples)
        ip_changes = np.random.binomial(n=1, p=0.05, size=n_samples)
        request_rates = np.random.normal(loc=15, scale=5, size=n_samples).clip(min=1)

        X_normal = np.column_stack([
            failed_logins,
            hour_deviations,
            targeted_accounts,
            ip_changes,
            request_rates
        ])

        # Inject 3% synthetic anomalies for robust boundary tuning
        n_anomalies = 50
        anomalies_failed = np.random.randint(8, 35, size=n_anomalies)
        anomalies_hours = np.random.uniform(6, 12, size=n_anomalies)
        anomalies_targets = np.random.randint(3, 10, size=n_anomalies)
        anomalies_ips = np.random.randint(3, 8, size=n_anomalies)
        anomalies_rates = np.random.uniform(80, 250, size=n_anomalies)

        X_anomalous = np.column_stack([
            anomalies_failed,
            anomalies_hours,
            anomalies_targets,
            anomalies_ips,
            anomalies_rates
        ])

        X_train = np.vstack([X_normal, X_anomalous])
        self.model.fit(X_train)

    def analyze_event_batch(self, event_features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyzes a batch of candidate telemetry events and assigns anomaly scores.
        """
        if not event_features:
            return []

        df = pd.DataFrame(event_features)
        feature_cols = [
            "failed_logins",
            "hour_deviation",
            "targeted_accounts",
            "ip_changes",
            "request_rate"
        ]

        # Ensure all columns exist with defaults
        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0

        X = df[feature_cols].values
        # Isolation Forest decision_function: lower score = more anomalous
        raw_scores = self.model.decision_function(X)
        predictions = self.model.predict(X) # -1 = outlier, 1 = normal

        results = []
        for i, (pred, score) in enumerate(zip(predictions, raw_scores)):
            is_anomaly = pred == -1 or score < 0.05
            # Normalize anomaly magnitude between 0.0 (normal) and 1.0 (extreme outlier)
            anomaly_magnitude = float(np.clip(1.0 - (score + 0.3) / 0.6, 0.0, 1.0))

            if is_anomaly or anomaly_magnitude >= 0.65:
                results.append({
                    "event_id": str(df.iloc[i].get("event_id", uuid.uuid4())),
                    "source_ip": str(df.iloc[i].get("source_ip", "198.51.100.42")),
                    "username": df.iloc[i].get("username"),
                    "anomaly_score": round(anomaly_magnitude, 2),
                    "reason": f"Isolation Forest Outlier (Score {round(anomaly_magnitude, 2)}): Multi-variable divergence across authentication rate and temporal distribution."
                })

        return results

    def generate_demo_anomaly_analysis(self) -> Dict[str, Any]:
        """
        Generates analysis on simulated live telemetry window.
        """
        synthetic_stream = [
            {"event_id": str(uuid.uuid4()), "source_ip": "10.0.0.15", "username": "admin@securewatch.local", "failed_logins": 0, "hour_deviation": 1.0, "targeted_accounts": 1, "ip_changes": 0, "request_rate": 12},
            {"event_id": str(uuid.uuid4()), "source_ip": "192.168.1.100", "username": "analyst@securewatch.local", "failed_logins": 0, "hour_deviation": 0.5, "targeted_accounts": 1, "ip_changes": 0, "request_rate": 18},
            {"event_id": str(uuid.uuid4()), "source_ip": "198.51.100.42", "username": "root@securewatch.local", "failed_logins": 18, "hour_deviation": 8.0, "targeted_accounts": 4, "ip_changes": 3, "request_rate": 140},
            {"event_id": str(uuid.uuid4()), "source_ip": "185.220.101.5", "username": "finance.lead@securewatch.local", "failed_logins": 6, "hour_deviation": 6.5, "targeted_accounts": 1, "ip_changes": 2, "request_rate": 75},
            {"event_id": str(uuid.uuid4()), "source_ip": "10.0.0.22", "username": "dev@securewatch.local", "failed_logins": 1, "hour_deviation": 2.0, "targeted_accounts": 1, "ip_changes": 0, "request_rate": 22}
        ]

        anomalies = self.analyze_event_batch(synthetic_stream)
        return {
            "analyzed_events_count": len(synthetic_stream),
            "anomalies_detected_count": len(anomalies),
            "anomaly_items": anomalies
        }

