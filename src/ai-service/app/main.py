from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router

app = FastAPI(
    title="SecureWatch AI Microservice",
    description="Python FastAPI service for Isolation Forest Anomaly Detection, Incident Intelligence, and Security Analytics",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "SecureWatch AI Microservice",
        "models": {
            "isolation_forest": "loaded_and_ready",
            "incident_analyzer": "operational",
            "report_generator": "operational",
            "chat_assistant": "operational"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

