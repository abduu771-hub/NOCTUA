"""
detection_engine/models.py
Event dataclass and ES-hit-to-Event mapping.

FIELD CONTRACT (HARD STOP):
    event.action       → event_type      (primary detection signal)
    source.ip          → source_ip
    user.name          → user
    user.effective.name→ effective_user
    @timestamp         → timestamp       (UTC-aware datetime)
    process.name       → program
    process.command_line→ command_line
    host.name          → host
    message            → raw_log
    tags               → tags; used by rule_engine.py for noise/ready_for_detection context
    destination.ip     → destination_ip
    destination.port   → destination_port
    network.transport  → network_transport
    network.protocol   → network_protocol
    network.bytes      → network_bytes
    network.packets    → network_packets
    dns.question.name  → dns_question_name
    event.dataset      → event_dataset

NO raw log parsing. NO Wazuh field names. NO invented fields.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

log = logging.getLogger("detection_engine.models")


# ── Event dataclass ───────────────────────────────────────────────────────────

@dataclass
class Event:
    # Core classification — REQUIRED
    event_type: str             # event.action value, e.g. "ssh_failed_login"

    # Network fields
    source_ip: Optional[str]    # IPv4/IPv6 of connecting client, or None
    source_port: Optional[int]  # Integer port or None

    # Destination / Network fields
    destination_ip: Optional[str]
    destination_port: Optional[int]
    network_transport: Optional[str]
    network_protocol: Optional[str]
    network_bytes: Optional[int]
    network_packets: Optional[int]
    dns_question_name: Optional[str]
    event_dataset: Optional[str]

    # Authentication fields
    user: Optional[str]              # user.name — target username
    effective_user: Optional[str]    # user.effective.name — elevation target

    # Timing — REQUIRED
    timestamp: datetime         # UTC-aware datetime; events with bad ts are dropped

    # Raw data (for alert context)
    raw_log: str                # Original message field from ES
    tags: List[str]             # Logstash tags

    # Source metadata
    program: str                # process.name — e.g. "sshd", "sudo"
    command_line: Optional[str] # process.command_line — for sudo_command events
    host: Optional[str]         # host.name

    # ES document identity — REQUIRED for dedup / checkpoint
    es_doc_id: str
    es_index: str


# ── Timestamp parser ──────────────────────────────────────────────────────────

def parse_timestamp(ts_string: str) -> datetime:
    """
    Parse an ISO-8601 timestamp from Elasticsearch into a UTC-aware datetime.

    Examples handled:
        '2026-04-27T10:00:00.000Z'
        '2026-04-27T10:00:00+00:00'

    Raises ValueError on unparseable input — caller must drop the event.
    """
    if not ts_string:
        raise ValueError("Empty timestamp string")

    try:
        # ES timestamps end with 'Z' — convert to +00:00 for fromisoformat
        if ts_string.endswith("Z"):
            ts_string = ts_string[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_string)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    # Fallback: python-dateutil (if installed)
    try:
        import dateutil.parser  # type: ignore[import-untyped]
        dt = dateutil.parser.parse(ts_string)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        raise ValueError(f"Cannot parse timestamp: {ts_string!r}")


# ── ES hit → Event factory ───────────────────────────────────────────────────

def _to_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _deep_get(d: dict, dotted_key: str, default=None):
    """
    Resolve a dotted key path against a nested dict.
    Example: _deep_get(src, "event.action") → src["event"]["action"]
    """
    keys = dotted_key.split(".")
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is default:
            return default
    return d


def event_from_es_hit(hit: dict) -> Event:
    """
    Build an Event from a raw Elasticsearch hit dict.

    hit = {"_id": ..., "_index": ..., "_source": {...}}

    Raises ValueError if the timestamp cannot be parsed.
    """
    source = hit.get("_source", {})

    # ── Map ECS fields to Event attributes ────────────────────────────────
    event_type = _deep_get(source, "event.action")
    if not event_type:
        event_type = "unknown"

    source_ip = _deep_get(source, "source.ip") or None
    user = _deep_get(source, "user.name") or None
    effective_user = _deep_get(source, "user.effective.name") or None
    program = _deep_get(source, "process.name") or "unknown"
    command_line = _deep_get(source, "process.command_line") or None
    host = _deep_get(source, "host.name") or None
    raw_log = source.get("message", "")

    tags_raw = source.get("tags", [])
    if not isinstance(tags_raw, list):
        tags_raw = []
    tags = [str(t).strip() for t in tags_raw if t is not None and str(t).strip()]

    # Port: not a standard ECS field in this pipeline, but handle if present
    source_port = _to_int(_deep_get(source, "source.port"))

    # Destination / Network mapping
    destination_ip = _deep_get(source, "destination.ip") or None
    destination_port = _to_int(_deep_get(source, "destination.port"))
    network_transport = _deep_get(source, "network.transport") or None
    network_protocol = _deep_get(source, "network.protocol") or None
    network_bytes = _to_int(_deep_get(source, "network.bytes"))
    network_packets = _to_int(_deep_get(source, "network.packets"))
    dns_question_name = _deep_get(source, "dns.question.name") or None
    event_dataset = _deep_get(source, "event.dataset") or None

    # Timestamp — CRITICAL: drop event if unparseable
    ts_raw = source.get("@timestamp", "")
    timestamp = parse_timestamp(ts_raw)   # raises ValueError → caller drops

    return Event(
        event_type=event_type,
        source_ip=source_ip if source_ip else None,
        source_port=source_port,
        destination_ip=destination_ip if destination_ip else None,
        destination_port=destination_port,
        network_transport=network_transport if network_transport else None,
        network_protocol=network_protocol if network_protocol else None,
        network_bytes=network_bytes,
        network_packets=network_packets,
        dns_question_name=dns_question_name if dns_question_name else None,
        event_dataset=event_dataset if event_dataset else None,
        user=user if user else None,
        effective_user=effective_user if effective_user else None,
        timestamp=timestamp,
        raw_log=raw_log,
        tags=tags,
        program=program,
        command_line=command_line,
        host=host,
        es_doc_id=hit["_id"],
        es_index=hit["_index"],
    )
