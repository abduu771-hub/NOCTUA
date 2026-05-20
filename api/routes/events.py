from fastapi import APIRouter, Query
from typing import Optional, List
from api.elastic import es_search

router = APIRouter()

@router.get("/events")
def get_events(
    size: int = Query(50, le=500),
    event_action: Optional[str] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
    source_ip: Optional[str] = None
):
    query = {"bool": {"must": []}}
    
    if event_action:
        query["bool"]["must"].append({"match": {"event.action": event_action}})
    if host:
        query["bool"]["must"].append({"match": {"host.name": host}})
    if user:
        query["bool"]["must"].append({"multi_match": {"query": user, "fields": ["user.name", "user.effective.name"]}})
    if source_ip:
        query["bool"]["must"].append({"match": {"source.ip": source_ip}})
        
    if not query["bool"]["must"]:
        query = {"match_all": {}}

    body = {
        "query": query,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    search_results = es_search("siem-raw-*", body, size=size)
    if "error" in search_results:
        return {"error": search_results["error"], "events": []}
        
    events = []
    for hit in search_results.get("hits", []):
        source = hit.get("_source", {})
        
        # Safely extract requested fields
        event_doc = {
            "_id": hit.get("_id"),
            "_index": hit.get("_index"),
            "@timestamp": source.get("@timestamp"),
            "event": {"action": source.get("event", {}).get("action") if isinstance(source.get("event"), dict) else source.get("event.action")},
            "source": {"ip": source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else source.get("source.ip")},
            "user": {
                "name": source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user.name"),
                "effective": {"name": source.get("user", {}).get("effective", {}).get("name") if isinstance(source.get("user"), dict) and isinstance(source.get("user").get("effective"), dict) else None}
            },
            "host": {"name": source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host.name")},
            "process": {
                "name": source.get("process", {}).get("name") if isinstance(source.get("process"), dict) else source.get("process.name"),
                "command_line": source.get("process", {}).get("command_line") if isinstance(source.get("process"), dict) else source.get("process.command_line")
            },
            "message": source.get("message"),
            "tags": source.get("tags", [])
        }
        events.append(event_doc)
        
    return events
