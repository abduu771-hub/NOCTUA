from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from api.elastic import es_search, get_es_client

router = APIRouter()
es_client = get_es_client()

@router.get("/alerts")
def get_alerts(
    size: int = Query(50, le=500),
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    user: Optional[str] = None,
    source_ip: Optional[str] = None,
    host: Optional[str] = None
):
    query = {"bool": {"must": []}}
    
    if severity:
        query["bool"]["must"].append({"match": {"severity": severity}})
    if rule_id:
        query["bool"]["must"].append({"match": {"rule.id": rule_id}})
    if user:
        query["bool"]["must"].append({"match": {"user.name": user}})
    if source_ip:
        query["bool"]["must"].append({"match": {"source.ip": source_ip}})
    if host:
        query["bool"]["must"].append({"match": {"host.name": host}})
        
    if not query["bool"]["must"]:
        query = {"match_all": {}}

    body = {
        "query": query,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    search_results = es_search("siem-alerts-*", body, size=size)
    if "error" in search_results:
        return {"error": search_results["error"], "alerts": []}
        
    alerts = []
    for hit in search_results.get("hits", []):
        source = hit.get("_source", {})
        
        alert_doc = {
            "_id": hit.get("_id"),
            "_index": hit.get("_index"),
            "@timestamp": source.get("@timestamp"),
            "rule": source.get("rule", {}),
            "event": source.get("event", {}),
            "source": source.get("source", {}),
            "user": {"name": source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user.name")},
            "host": source.get("host", {}),
            "evidence": source.get("evidence", {}),
            "correlation": source.get("correlation", {}),
            "mitre": source.get("mitre", {}),
            "engine": source.get("engine", {})
        }
        alerts.append(alert_doc)
        
    return alerts

@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    query = {
        "query": {
            "ids": {
                "values": [alert_id]
            }
        }
    }
    search_results = es_search("siem-alerts-*", query, size=1)
    if "error" in search_results:
        raise HTTPException(status_code=500, detail=search_results["error"])
        
    hits = search_results.get("hits", [])
    if not hits:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    hit = hits[0]
    return {
        "_id": hit.get("_id"),
        "_index": hit.get("_index"),
        **hit.get("_source", {})
    }
