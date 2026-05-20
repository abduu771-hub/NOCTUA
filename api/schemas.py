from typing import Any, Dict, List
from pydantic import BaseModel

class HealthResponse(BaseModel):
    status: str
    service: str

class OverviewResponse(BaseModel):
    total_events: int
    total_alerts: int
    total_incidents: int
    open_incidents: int
    critical_alerts: int
    latest_alert_time: str | None
    latest_incident_time: str | None

# Responses for events, alerts, and incidents will mostly be dicts matching requested fields
