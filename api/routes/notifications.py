"""
api/routes/notifications.py

Live notification feed for the SOC dashboard.

Architecture note: this route does NOT talk to the detection engine.
It only polls Elasticsearch — consistent with the rest of this API.
The engine writes incidents/alerts; this route reads them. No shared
memory, no direct coupling to incident_engine.py / cross_layer_engine.py /
alert_writer.py.

Notification types (8, all backed by fields that already exist):
  incident_created           - new incident appears (siem-incidents-*)
  incident_closed            - incident status -> closed
  incident_reopened          - incident status -> open (after being closed)
  incident_updated           - severity rank increased on an open incident
  cross_layer_correlation    - new cross-layer incident (incident.is_cross_layer)
  alert_created               - new alert fires (siem-alerts-*)
  alert_closed                - alert status -> CLOSED (admin action)
  alert_reopened               - alert status -> OPEN (admin action, after closed)

Per-connection cache:
  Detecting "closed vs reopened" and "severity went up" requires knowing
  the PREVIOUS state of a given incident/alert, not just "is this newer
  than my cursor". We keep a small in-memory dict scoped to a single SSE
  connection's lifetime (last_known_status / last_known_severity per id).
  This is disposable: if the API restarts, a reconnecting client just
  rebuilds the cache from scratch and silently skips emitting deltas for
  one cycle. Nothing the engine depends on, nothing that breaks a restart.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from api.elastic import get_es_client
from detection_engine.lifecycle_contract import (
    ALERT_STATUS_OPEN,
    ALERT_STATUS_CLOSED,
)

log = logging.getLogger("api.routes.notifications")

router = APIRouter()

INCIDENT_INDEX_PATTERN = "siem-incidents-*"
ALERT_INDEX_PATTERN = "siem-alerts-*"
POLL_INTERVAL_SECONDS = 3

_SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _sev_rank(severity) -> int:
    return _SEVERITY_RANK.get(str(severity or "").upper(), 0)


# ─────────────────────────────────────────────────────────────────────────
# INCIDENT POLLING (incident_created / incident_closed / incident_reopened /
#                    incident_updated / cross_layer_correlation)
# ─────────────────────────────────────────────────────────────────────────

def _fetch_incident_events(es, since_iso: str, known_state: dict) -> list[dict]:
    """
    Query siem-incidents-* for incidents created or status-changed after
    `since_iso`. Uses `known_state` (keyed by incident_id) to detect the
    DIRECTION of a status change and whether severity increased.

    Never raises — mirrors es_search's safety pattern (existence check,
    broad except, empty list on failure).
    """
    try:
        if not es.indices.exists(index=INCIDENT_INDEX_PATTERN):
            return []

        query = {
            "size": 100,
            "sort": [{"updated_at": {"order": "asc"}}],
            "query": {
                "bool": {
                    "should": [
                        {"range": {"incident.created_at": {"gt": since_iso}}},
                        {"range": {"incident.last_status_change": {"gt": since_iso}}},
                        {"range": {"updated_at": {"gt": since_iso}}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        }

        res = es.search(index=INCIDENT_INDEX_PATTERN, body=query)
        hits = res.get("hits", {}).get("hits", [])

    except Exception as exc:
        log.error("Incident notification poll failed: %s", exc)
        return []

    events = []

    for hit in hits:
        src = hit.get("_source", {})
        incident = src.get("incident", {})

        incident_id = incident.get("id")
        if not incident_id:
            continue

        created_at = src.get("created_at")
        opened_at = incident.get("opened_at")
        last_status_change = incident.get("last_status_change")
        current_status = (incident.get("status") or "").lower()
        current_severity = incident.get("severity")
        is_cross_layer = bool(incident.get("is_cross_layer"))

        prev = known_state.get(incident_id)

        base_payload = {
            "incident_id": incident_id,
            "incident_name": incident.get("name"),
            "incident_type": incident.get("type"),
            "severity": current_severity,
            "status": incident.get("status"),
            "grouping_key": incident.get("grouping_key"),
        }

        # ── First time we've ever seen this incident ───────────────────
        if prev is None:
            is_new = bool(created_at) and created_at == opened_at

            if is_cross_layer and is_new:
                events.append({
                    **base_payload,
                    "kind": "cross_layer_correlation",
                    "occurred_at": created_at,
                })
            elif is_new:
                events.append({
                    **base_payload,
                    "kind": "incident_created",
                    "occurred_at": created_at,
                })
            else:
                # Pre-existing incident we're observing for the first time
                # in this connection (e.g. it changed before we connected,
                # or this is a severity bump on something already open).
                # Don't fabricate a "created" event for it — just seed the
                # cache so future deltas are detected correctly.
                pass

            known_state[incident_id] = {
                "status": current_status,
                "severity": current_severity,
            }
            continue

        # ── We've seen this incident before — diff against last state ──
        prev_status = prev.get("status")
        prev_severity = prev.get("severity")

        if current_status != prev_status:
            if current_status == "closed":
                events.append({
                    **base_payload,
                    "kind": "incident_closed",
                    "occurred_at": last_status_change,
                })
            elif current_status == "open" and prev_status == "closed":
                events.append({
                    **base_payload,
                    "kind": "incident_reopened",
                    "occurred_at": last_status_change,
                })

        elif _sev_rank(current_severity) > _sev_rank(prev_severity):
            events.append({
                **base_payload,
                "kind": "incident_updated",
                "occurred_at": last_status_change or created_at,
            })

        known_state[incident_id] = {
            "status": current_status,
            "severity": current_severity,
        }

    return events


# ─────────────────────────────────────────────────────────────────────────
# ALERT POLLING (alert_created / alert_closed / alert_reopened)
# ─────────────────────────────────────────────────────────────────────────

def _fetch_alert_events(es, since_iso: str, known_state: dict) -> list[dict]:
    """
    Query siem-alerts-* for alerts created or status-changed after
    `since_iso`. Mirrors _fetch_incident_events but for the alert
    lifecycle (admin-driven OPEN/CLOSED via PATCH /alerts/{id}/status).
    """
    try:
        if not es.indices.exists(index=ALERT_INDEX_PATTERN):
            return []

        query = {
            "size": 100,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "should": [
                        {"range": {"opened_at": {"gt": since_iso}}},
                        {"range": {"last_status_change": {"gt": since_iso}}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        }

        res = es.search(index=ALERT_INDEX_PATTERN, body=query)
        hits = res.get("hits", {}).get("hits", [])

    except Exception as exc:
        log.error("Alert notification poll failed: %s", exc)
        return []

    events = []

    for hit in hits:
        src = hit.get("_source", {})

        alert_doc_id = hit.get("_id")
        alert_business_id = (src.get("alert") or {}).get("id") or alert_doc_id
        if not alert_business_id:
            continue

        opened_at = src.get("opened_at")
        last_status_change = src.get("last_status_change")
        current_status = (src.get("status") or ALERT_STATUS_OPEN).upper()
        rule = src.get("rule", {})

        prev = known_state.get(alert_business_id)

        base_payload = {
            "alert_id": alert_business_id,
            "rule_id": rule.get("id"),
            "severity": rule.get("severity"),
            "status": current_status,
            "source_ip": (src.get("source") or {}).get("ip"),
            "host": (src.get("host") or {}).get("name"),
        }

        # ── First time we've seen this alert ────────────────────────────
        if prev is None:
            is_new = bool(opened_at) and (
                last_status_change is None or last_status_change == opened_at
            )

            if is_new:
                events.append({
                    **base_payload,
                    "kind": "alert_created",
                    "occurred_at": opened_at,
                })

            known_state[alert_business_id] = {"status": current_status}
            continue

        # ── Diff against last known status ──────────────────────────────
        prev_status = prev.get("status")

        if current_status != prev_status:
            if current_status == ALERT_STATUS_CLOSED:
                events.append({
                    **base_payload,
                    "kind": "alert_closed",
                    "occurred_at": last_status_change,
                })
            elif current_status == ALERT_STATUS_OPEN and prev_status == ALERT_STATUS_CLOSED:
                events.append({
                    **base_payload,
                    "kind": "alert_reopened",
                    "occurred_at": last_status_change,
                })

        known_state[alert_business_id] = {"status": current_status}

    return events


# ─────────────────────────────────────────────────────────────────────────
# SSE ENDPOINT
# ─────────────────────────────────────────────────────────────────────────

@router.get("/notifications/stream")
async def notifications_stream():
    """
    SSE endpoint. Polls Elasticsearch every POLL_INTERVAL_SECONDS for
    incident and alert events, and pushes them to the connected dashboard
    client as they're detected.

    Each connection gets its own cursor + state cache (incident_state,
    alert_state). Reconnects start fresh from "now" — no event backlog
    is replayed, and no state survives a disconnect. This keeps the
    endpoint stateless across connections, matching the rest of the API.
    """
    es = get_es_client()

    async def event_generator():
        since_iso = datetime.now(timezone.utc).isoformat()
        incident_state: dict = {}
        alert_state: dict = {}

        while True:
            incident_events = await asyncio.to_thread(
                _fetch_incident_events, es, since_iso, incident_state
            )
            alert_events = await asyncio.to_thread(
                _fetch_alert_events, es, since_iso, alert_state
            )

            all_events = incident_events + alert_events
            all_events.sort(key=lambda e: e.get("occurred_at") or "")

            for event in all_events:
                occurred_at = event.get("occurred_at")
                if occurred_at and occurred_at > since_iso:
                    since_iso = occurred_at
                yield f"data: {json.dumps(event)}\n\n"

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )