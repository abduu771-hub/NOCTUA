from fastapi import APIRouter
from datetime import datetime, timezone
from api.elastic import get_es_client

router = APIRouter()
es_client = get_es_client()

def get_sources_agg(field_name: str):
    body = {
        "size": 0,
        "aggs": {
            "hosts": {
                "terms": {"field": field_name, "size": 1000},
                "aggs": {
                    "latest_event": {
                        "max": {"field": "@timestamp"}
                    }
                }
            }
        }
    }
    return es_client.search(index="siem-raw-*", body=body)

@router.get("/sources")
def get_sources():
    try:
        if not es_client.indices.exists(index="siem-raw-*"):
            return []
            
        try:
            # Try grouping by keyword first
            res = get_sources_agg("host.name.keyword")
        except Exception:
            # Fallback to host.name
            res = get_sources_agg("host.name")
            
        buckets = res.get("aggregations", {}).get("hosts", {}).get("buckets", [])
        
        sources = []
        now = datetime.now(timezone.utc).timestamp()
        
        for bucket in buckets:
            host_name = bucket["key"]
            event_count = bucket["doc_count"]
            last_event_ts = bucket["latest_event"]["value_as_string"] if "value_as_string" in bucket["latest_event"] else bucket["latest_event"]["value"]
            
            # Determine status
            status = "unknown"
            if "latest_event" in bucket and bucket["latest_event"]["value"]:
                # value is usually in milliseconds
                latest_ms = bucket["latest_event"]["value"]
                latest_sec = latest_ms / 1000.0
                
                # if within last 10 minutes (600 seconds)
                if now - latest_sec <= 600:
                    status = "active"
                else:
                    status = "stale"
                    
            sources.append({
                "host": host_name,
                "event_count": event_count,
                "last_event_timestamp": last_event_ts,
                "status": status
            })
            
        return sources
    except Exception as e:
        return {"error": str(e), "sources": []}
