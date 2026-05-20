from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from api.elastic import es_search, get_es_client

router = APIRouter()
es_client = get_es_client()

@router.get("/incidents")
def get_incidents(
    size: int = Query(50, le=500),
    status: Optional[str] = None,
    incident_type: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None
):
    query = {"bool": {"must": []}}
    
    if status:
        query["bool"]["must"].append({"match": {"incident.status": status}})
    if incident_type:
        query["bool"]["must"].append({"match": {"incident.incident_type": incident_type}})
    if user:
        query["bool"]["must"].append({"match": {"attack_context.users_seen": user}})
    if host:
        query["bool"]["must"].append({"match": {"host.name": host}})
        
    if not query["bool"]["must"]:
        query = {"match_all": {}}

    body = {
        "query": query,
        "sort": [{"updated_at": {"order": "desc"}}]
    }
    
    search_results = es_search("siem-incidents-*", body, size=size)
    if "error" in search_results:
        return {"error": search_results["error"], "incidents": []}
        
    incidents = []
    for hit in search_results.get("hits", []):
        source = hit.get("_source", {})
        
        incident_doc = {
            "_id": hit.get("_id"),
            "_index": hit.get("_index"),
            "incident": source.get("incident", {}),
            "source": source.get("source", {}),
            "host": source.get("host", {}),
            "attack_context": source.get("attack_context", {}),
            "related": source.get("related", {}),
            "created_at": source.get("created_at"),
            "updated_at": source.get("updated_at")
        }
        incidents.append(incident_doc)
        
    return incidents

def fetch_incident(incident_id: str):
    # Try finding by doc _id first
    query_id = {"query": {"ids": {"values": [incident_id]}}}
    res = es_search("siem-incidents-*", query_id, size=1)
    if res.get("hits"):
        return res["hits"][0]
        
    # Fallback finding by incident.id
    query_inc_id = {"query": {"term": {"incident.id.keyword": incident_id}}}
    res2 = es_search("siem-incidents-*", query_inc_id, size=1)
    if res2.get("hits"):
        return res2["hits"][0]
        
    return None

@router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    hit = fetch_incident(incident_id)
    if not hit:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    return {
        "_id": hit.get("_id"),
        "_index": hit.get("_index"),
        **hit.get("_source", {})
    }

@router.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str):
    hit = fetch_incident(incident_id)
    if not hit:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    source = hit.get("_source", {})
    
    related_rules = source.get("related", {}).get("rule_ids", [])
    users_seen = source.get("attack_context", {}).get("users_seen", [])
    
    # host could be a single string, list, or dict with names.
    host_data = source.get("host", {})
    host_names = []
    if isinstance(host_data, dict):
        if "name" in host_data:
            if isinstance(host_data["name"], list):
                host_names = host_data["name"]
            else:
                host_names = [host_data["name"]]
    elif isinstance(host_data, list):
        host_names = host_data
    elif isinstance(host_data, str):
        host_names = [host_data]

    # Build OR query
    should_clauses = []
    if related_rules:
        should_clauses.append({"terms": {"rule.id.keyword": related_rules}})
    if users_seen:
        should_clauses.append({"terms": {"user.name.keyword": users_seen}})
    if host_names:
        should_clauses.append({"terms": {"host.name.keyword": host_names}})
        
    # If no criteria can be formed, just return empty
    if not should_clauses:
        return []
        
    query = {
        "bool": {
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    body = {
        "query": query,
        "sort": [{"@timestamp": {"order": "asc"}}]
    }
    
    search_results = es_search("siem-alerts-*", body, size=500)
    if "error" in search_results:
        return {"error": search_results["error"], "timeline": []}
        
    timeline = []
    for alert_hit in search_results.get("hits", []):
        alert_source = alert_hit.get("_source", {})
        
        timeline.append({
            "rule": {
                "id": alert_source.get("rule", {}).get("id"),
                "description": alert_source.get("rule", {}).get("description")
            },
            "severity": alert_source.get("severity"),
            "user": {"name": alert_source.get("user", {}).get("name") if isinstance(alert_source.get("user"), dict) else alert_source.get("user.name")},
            "source": {"ip": alert_source.get("source", {}).get("ip") if isinstance(alert_source.get("source"), dict) else alert_source.get("source.ip")},
            "host": {"name": alert_source.get("host", {}).get("name") if isinstance(alert_source.get("host"), dict) else alert_source.get("host.name")},
            "evidence": alert_source.get("evidence"),
            "correlation": alert_source.get("correlation"),
            "@timestamp": alert_source.get("@timestamp")
        })
        
    return timeline
