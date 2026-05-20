from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.schemas import HealthResponse

from api.routes.overview import router as overview_router
from api.routes.events import router as events_router
from api.routes.alerts import router as alerts_router
from api.routes.incidents import router as incidents_router
from api.routes.sources import router as sources_router

app = FastAPI(title="SIEM-AI API", description="Read-only backend for SIEM-AI UI")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "ok",
        "service": "siem-ai-api"
    }

# Include routers
app.include_router(overview_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(sources_router, prefix="/api")
