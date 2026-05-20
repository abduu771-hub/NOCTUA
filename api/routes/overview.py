from fastapi import APIRouter
from api.elastic import es_count, es_search
from api.schemas import OverviewResponse

router = APIRouter()

@router.get("/overview", response_model=OverviewResponse)
def get_overview():
    # Counts
    events_count = es_count("siem-raw-*")
    alerts_count = es_count("siem-alerts-*")
    incidents_count = es_count("siem-incidents-*")
    
    # Open incidents
    open_incidents_query = {
        "query": {
            "term": {
                "incident.status.keyword": "open"
            }
        }
    }
    # Fallback to status without keyword if keyword is not indexed
    open_incidents = es_count("siem-incidents-*", open_incidents_query)
    if open_incidents == 0:
        open_incidents = es_count("siem-incidents-*", {"query": {"term": {"incident.status": "open"}}})

    # Critical alerts
    critical_alerts_query = {
        "query": {
            "term": {
                "severity.keyword": "critical"
            }
        }
    }
    critical_alerts = es_count("siem-alerts-*", critical_alerts_query)
    if critical_alerts == 0:
        critical_alerts = es_count("siem-alerts-*", {"query": {"term": {"severity": "critical"}}})

    # Latest timestamps
    latest_alert_time = None
    alert_search = es_search("siem-alerts-*", {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc"}}]}, size=1)
    if alert_search.get("hits"):
        latest_alert_time = alert_search["hits"][0]["_source"].get("@timestamp")

    latest_incident_time = None
    inc_search = es_search("siem-incidents-*", {"query": {"match_all": {}}, "sort": [{"updated_at": {"order": "desc"}}]}, size=1)
    if inc_search.get("hits"):
        latest_incident_time = inc_search["hits"][0]["_source"].get("updated_at")

    return {
        "total_events": events_count,
        "total_alerts": alerts_count,
        "total_incidents": incidents_count,
        "open_incidents": open_incidents,
        "critical_alerts": critical_alerts,
        "latest_alert_time": latest_alert_time,
        "latest_incident_time": latest_incident_time
    }
