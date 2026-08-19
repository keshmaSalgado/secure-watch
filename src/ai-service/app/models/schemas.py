from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class IncidentAnalysisRequest(BaseModel):
    incident_id: str
    code: str
    title: str
    description: str
    severity: str
    risk_score: int
    source_ip: Optional[str] = None
    events: List[Dict[str, Any]] = []

class IncidentAnalysisResponse(BaseModel):
    incident_id: str
    summary: str
    attack_category: str
    suspicious_indicators: List[str]
    potential_impact: str
    recommendations: List[str]
    confidence_score: str
    is_deterministic_fallback: bool = False

class ReportRequest(BaseModel):
    report_type: str = "DailySummary"
    total_events: int = 0
    total_threats: int = 0
    critical_incidents: int = 0
    resolved_incidents: int = 0

class ReportResponse(BaseModel):
    title: str
    executive_summary: str
    key_observations: List[str]
    critical_risk_areas: List[str]
    recommended_mitigations: List[str]
    generated_at_utc: datetime = Field(default_factory=datetime.utcnow)
    is_deterministic_fallback: bool = False

class ChatRequest(BaseModel):
    query: str
    incident_id: Optional[str] = None
    ip_address: Optional[str] = None

class ChatResponse(BaseModel):
    answer: str
    referenced_entities: List[str] = []
    suggested_followups: List[str] = []
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)

class AnomalyScoreItem(BaseModel):
    event_id: str
    source_ip: str
    username: Optional[str] = None
    anomaly_score: float
    reason: str

class AnomalyDetectionResponse(BaseModel):
    analyzed_events_count: int
    anomalies_detected_count: int
    anomaly_items: List[AnomalyScoreItem] = []
    analyzed_at_utc: datetime = Field(default_factory=datetime.utcnow)

