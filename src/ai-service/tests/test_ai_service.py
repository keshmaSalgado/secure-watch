import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add app directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.services.anomaly_detector import AnomalyDetectionEngine

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "models" in data
    assert data["models"]["isolation_forest"] == "loaded_and_ready"

def test_isolation_forest_anomaly_detection():
    engine = AnomalyDetectionEngine()
    result = engine.generate_demo_anomaly_analysis()
    
    assert "analyzed_events_count" in result
    assert result["analyzed_events_count"] > 0
    assert "anomaly_items" in result
    assert isinstance(result["anomaly_items"], list)
    
    # Anomaly items should contain valid outlier scores between 0.0 and 1.0
    for item in result["anomaly_items"]:
        assert 0.0 <= item["anomaly_score"] <= 1.0
        assert "event_id" in item
        assert "source_ip" in item

def test_analyze_incident_endpoint():
    payload = {
        "incident_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "code": "SEC-2026-0001",
        "title": "Brute Force Attack on Admin",
        "description": "Multiple failed logins from 198.51.100.42 within 1 minute",
        "severity": "High",
        "risk_score": 85,
        "source_ip": "198.51.100.42",
        "events": [
            {
                "EventType": "UserLoginFailed",
                "Category": "FailedLogin",
                "Severity": "High",
                "SourceIp": "198.51.100.42",
                "Description": "Invalid password"
            }
        ]
    }
    response = client.post("/api/v1/ai/analyze-incident", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert "attack_category" in data
    assert "recommendations" in data
    assert len(data["recommendations"]) > 0

def test_generate_report_endpoint():
    payload = {
        "report_type": "WeeklyThreats",
        "total_events": 1500,
        "total_threats": 24,
        "critical_incidents": 3,
        "resolved_incidents": 20
    }
    response = client.post("/api/v1/ai/generate-report", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "title" in data
    assert "executive_summary" in data
    assert "key_observations" in data
    assert "critical_risk_areas" in data
    assert "recommended_mitigations" in data

def test_chat_endpoint():
    payload = {
        "query": "What were the most critical security incidents today?"
    }
    response = client.post("/api/v1/ai/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "suggested_followups" in data
    assert len(data["suggested_followups"]) > 0

