from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.models.schemas import (
    IncidentAnalysisRequest, IncidentAnalysisResponse,
    ReportRequest, ReportResponse,
    ChatRequest, ChatResponse,
    AnomalyDetectionResponse
)
from app.services.anomaly_detector import AnomalyDetectionEngine
from app.services.incident_analyzer import IncidentAnalyzer
from app.services.report_generator import SecurityReportGenerator
from app.services.chat_assistant import SecurityChatAssistant

router = APIRouter(prefix="/api/v1/ai", tags=["AI Security"])

anomaly_engine = AnomalyDetectionEngine()
incident_analyzer = IncidentAnalyzer()
report_generator = SecurityReportGenerator()
chat_assistant = SecurityChatAssistant()

@router.post("/analyze-incident", response_model=IncidentAnalysisResponse)
async def analyze_incident(request: IncidentAnalysisRequest):
    try:
        result = incident_analyzer.analyze(request.model_dump())
        return IncidentAnalysisResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate-report", response_model=ReportResponse)
async def generate_report(request: ReportRequest):
    try:
        result = report_generator.generate_report(request.model_dump())
        return ReportResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    try:
        result = chat_assistant.answer_query(
            query=request.query,
            context_incident_id=request.incident_id,
            context_ip=request.ip_address
        )
        return ChatResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/anomaly-detection", response_model=AnomalyDetectionResponse)
async def detect_anomalies():
    try:
        result = anomaly_engine.generate_demo_anomaly_analysis()
        return AnomalyDetectionResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

