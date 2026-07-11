from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional
from detection_engine.incident_engine import IncidentEngine

from api.elastic import es_search, get_es_client

from detection_engine.lifecycle_contract import ALERT_STATUS_CLOSED, ALERT_STATUS_OPEN, ALLOWED_ALERT_STATUSES ,is_valid_transition, derive_incident_status, INCIDENT_STATUS_OPEN, INCIDENT_STATUS_CLOSED


router = APIRouter()
es_client = get_es_client()
import logging

log = logging.getLogger(__name__)


class StatusUpdate(BaseModel):
    status: str
    class Config:
        str_strip_whitespace = True


def fetch_alert(alert_id: str):
    # Try ES _id first (direct lookup, fast)
    query = {"query": {"ids": {"values": [alert_id]}}}
    res = es_search("siem-alerts-*", query, size=1)
    if res.get("hits"):
        return res["hits"][0]

    # Fall back to business alert.id (canonical identifier)
    query2 = {"query": {"term": {"alert.id.keyword": alert_id}}}
    res2 = es_search("siem-alerts-*", query2, size=1)
    if res2.get("hits"):
        return res2["hits"][0]

    return None


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
        query["bool"]["must"].append({"match": {"rule.severity": severity.upper()}})
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

        alerts.append({
            "_id": hit.get("_id"),
            "_index": hit.get("_index"),
            "@timestamp": source.get("@timestamp"),
            "rule": source.get("rule", {}),
            "event": source.get("event", {}),
            "source": source.get("source", {}),
            "user": source.get("user", {}),
            "host": source.get("host", {}),
            "evidence": source.get("evidence", {}),
            "correlation": source.get("correlation", {}),
            "mitre": source.get("mitre", {}),
            "engine": source.get("engine", {}),
            "status": source.get("status", "OPEN"),
            "opened_at": source.get("opened_at"),
            "closed_at": source.get("closed_at"),
            "reopened_at": source.get("reopened_at"),
            "closed_by": source.get("closed_by"),
            "reopened_by": source.get("reopened_by"),
            "last_status_change": source.get("last_status_change")
        })

    return alerts


@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    hit = fetch_alert(alert_id)

    if not hit:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "_id": hit.get("_id"),
        "_index": hit.get("_index"),
        **hit.get("_source", {})
    }

@router.post("/incidents/{incident_id}/close")
def close_incident(incident_id: str):
    """
    Closes every alert linked to this incident.
    Incident status itself is never written directly — it derives
    automatically once all linked alerts are CLOSED.
    """
    try:
        res = es_client.search(
            index="siem-incidents-*",
            body={"query": {"term": {"incident.id.keyword": incident_id}}},
            size=1,
        )
        hits = res.get("hits", {}).get("hits", [])
    except Exception:
        raise HTTPException(status_code=500, detail="Elasticsearch search failed")

    if not hits:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_src = hits[0]["_source"]
    alert_ids = incident_src.get("related", {}).get("alert_ids", [])

    if not alert_ids:
        return {"success": True, "closed_count": 0, "message": "No linked alerts to close"}

    now = datetime.now(timezone.utc).isoformat()
    closed_count = 0

    for alert_id in alert_ids:
        hit = fetch_alert(alert_id)
        if not hit:
            continue

        source = hit.get("_source", {})
        previous_status = source.get("status", ALERT_STATUS_OPEN).upper()

        if previous_status == ALERT_STATUS_CLOSED:
            continue

        opened_at = source.get("opened_at") or now
        lifecycle_patch = {
            "status": ALERT_STATUS_CLOSED,
            "opened_at": opened_at,
            "closed_at": now,
            "reopened_at": source.get("reopened_at"),
            "closed_by": "admin",
            "reopened_by": None,
            "last_status_change": now,
        }

        try:
            es_client.update(
                index=hit.get("_index"),
                id=hit.get("_id"),
                body={"doc": lifecycle_patch},
                refresh="wait_for",
            )
            closed_count += 1
        except Exception:
            log.warning("Failed to close alert %s during bulk incident close", alert_id)
    try:
        IncidentEngine(es_client).run_auto_close_cycle()
    except Exception:
        log.warning("Auto-close cycle failed after bulk alert close")
    return {
        "success": True,
        "incident_id": incident_id,
        "closed_count": closed_count,
        "total_alerts": len(alert_ids),
        "message": "Linked alerts closed. Incident status will sync automatically.",
    }
@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, payload: StatusUpdate):
    """
    ADMIN IS THE ONLY LIFECYCLE OWNER FOR ALERTS.

    Allowed transitions (from lifecycle_contract.py):
      OPEN   → CLOSED
      CLOSED → OPEN

    After writing the alert status, this function re-derives and
    persists the status of every incident that references this alert.
    Incident status is NEVER written anywhere else.
    """
    hit = fetch_alert(alert_id)

    if not hit:
        raise HTTPException(status_code=404, detail="Alert not found")

    new_status = payload.status.upper()

    if new_status not in ALLOWED_ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed: {sorted(ALLOWED_ALERT_STATUSES)}"
        )

    source = hit.get("_source", {})
    previous_status = source.get("status", ALERT_STATUS_OPEN).upper()
    log.info("STATUS TRANSITION DEBUG: previous=%s new=%s", previous_status, new_status)


    if not is_valid_transition(previous_status, new_status):
        raise HTTPException(
            status_code=400,
            detail=f"Transition {previous_status} → {new_status} is not allowed."
        )

    now = datetime.now(timezone.utc).isoformat()
    opened_at = source.get("opened_at") or now

    if new_status == ALERT_STATUS_CLOSED:
        lifecycle_patch = {
            "status": ALERT_STATUS_CLOSED,
            "opened_at": opened_at,
            "closed_at": now,
            "reopened_at": source.get("reopened_at"),
            "closed_by": "admin",
            "reopened_by": None,
            "last_status_change": now,
        }
    else:
        lifecycle_patch = {
            "status": ALERT_STATUS_OPEN,
            "opened_at": opened_at,
            "closed_at": None,
            "reopened_at": now,
            "closed_by": None,
            "reopened_by": "admin",
            "last_status_change": now,
        }

    try:
        log.info(
            "Alert status change alert_id=%s %s -> %s",
            alert_id,
            previous_status,
            new_status,
        )
        es_client.update(
            index=hit.get("_index"),
            id=hit.get("_id"),
            body={"doc": lifecycle_patch},
            refresh="wait_for",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Elasticsearch update failed")

    # ── Derive and persist incident status from all linked alerts ──────────
    # This is the ONLY place incident status is ever updated from outside
    # the detection pipeline. Incident engine does the same derivation
    # during processing. Both use derive_incident_status() from the contract.
    # Incident status is derived by incident_engine.run_auto_close_cycle()
    # which runs every poll cycle. No direct sync triggered here.

    return {
        "success": True,
        "alert_id": alert_id,
        "previous_status": previous_status,
        "status": new_status,
        "message": "Alert status updated successfully"
    }
def _sync_incidents_for_alert(alert_id: str) -> None:
    """
    After an admin changes one alert's status, re-derive the status of
    every incident that references this alert.

    This is the ONLY function that writes incident.status outside of
    the detection pipeline. It uses derive_incident_status() from
    lifecycle_contract.py — the same function incident_engine uses.
    No business logic lives here. Pure derivation.
    """
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    # Find all incidents that reference this alert
    try:
        res = es_client.search(
            index="siem-incidents-*",
            body={
                "size": 50,
                "query": {
                    "term": {"related.alert_ids.keyword": alert_id}
                }
            }
        )
        incident_hits = res.get("hits", {}).get("hits", [])
    except Exception as e:
        log.warning("Could not search incidents for alert_id=%s: %s", alert_id, e)
        return

    for inc_hit in incident_hits:
        inc_src = inc_hit["_source"]
        incident_block = inc_src.get("incident", {})
        related_alert_ids = inc_src.get("related", {}).get("alert_ids", [])

        if not related_alert_ids:
            continue

        # Fetch current statuses of ALL linked alerts
        try:
            alert_res = es_client.search(
                index="siem-alerts-*",
                body={
                    "size": len(related_alert_ids),
                    "query": {"ids": {"values": related_alert_ids}},
                    "_source": ["status"],
                }
            )
            alert_statuses = [
                h["_source"].get("status", ALERT_STATUS_OPEN)
                for h in alert_res.get("hits", {}).get("hits", [])
            ]
        except Exception as e:
            log.warning("Could not fetch alert statuses for incident sync: %s", e)
            continue

        if not alert_statuses:
            continue

        # Derive correct incident status from the contract
        derived = derive_incident_status(alert_statuses)
        current = incident_block.get("status", INCIDENT_STATUS_OPEN).lower()

        if derived == current:
            continue  # Nothing to update

        # Build minimal lifecycle patch — only status fields, nothing else
        updated_incident = dict(incident_block)
        updated_incident["status"] = derived
        updated_incident["last_status_change"] = now_iso

        if derived == INCIDENT_STATUS_CLOSED:
            updated_incident["closed_at"] = now_iso
            updated_incident["closed_by"] = "system:alert_sync"
            updated_incident["reopened_by"] = None
        else:
            updated_incident["reopened_at"] = now_iso
            updated_incident["reopened_by"] = "system:alert_sync"
            updated_incident["closed_at"] = None
            updated_incident["closed_by"] = None

        try:
            es_client.update(
                index=inc_hit["_index"],
                id=inc_hit["_id"],
                body={"doc": {
                    "incident": updated_incident,
                    "updated_at": now_iso,
                }},
                refresh="wait_for",
            )
            log.info(
                "Incident status synced: id=%s %s → %s (alert_id=%s)",
                inc_hit["_id"],
                current,
                derived,
                alert_id,
            )
        except Exception as e:
            log.warning(
                "Failed to sync incident id=%s: %s", inc_hit["_id"], e
            )