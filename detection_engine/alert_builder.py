"""
detection_engine/alert_builder.py
Central alert document builder — the ONLY place final alert documents are created.

Produces clean ECS-nested documents that match the siem-alerts-* index template.
Never emits "N/A", "", "none", or "null" for structured fields.

Rule engine passes raw detection data here; this module returns a validated dict
ready for AlertWriter.write().

Permanent context model:
  - evidence.users_seen
  - evidence.source_ips_seen
  - evidence.hosts_seen
  - evidence.unique_users
  - evidence.unique_ips
  - correlation.users_seen
  - correlation.source_ips
  - correlation.host
  - correlation.strategy

This allows incident escalation to rely on structured context instead of
parsing raw log strings.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from .models import Event
from .rules import RuleDefinition

log = logging.getLogger("detection_engine.alert_builder")

ENGINE_NAME = "siem-ai-detection-engine"
ENGINE_VERSION = "2.1"

NETWORK_RULE_IDS = {
    "network_port_scan",
    "network_internal_sweep",
    "network_suspicious_outbound",
    "network_c2_beaconing",
    "network_suspicious_dns",
}

IDS_RULE_IDS = {
    "network_ids_malware",
    "network_ids_c2",
    "network_ids_exploit",
    "network_ids_scan_recon",
    "network_ids_credential",
    "network_ids_exfiltration",
    "network_ids_policy",
    "network_ids_protocol_anomaly",
    "network_ids_unknown_high",
}

NETWORK_RULE_TITLES = {
    "network_port_scan": "Network Port Scan Detected",
    "network_internal_sweep": "Internal Network Sweep Detected",
    "network_suspicious_outbound": "Suspicious Outbound Connection Detected",
    "network_c2_beaconing": "Possible C2 Beaconing Detected",
    "network_suspicious_dns": "Suspicious DNS Activity Detected",
}

IDS_RULE_TITLES = {
    "network_ids_malware": "Suricata IDS Malware Signature Detected",
    "network_ids_c2": "Suricata IDS Command and Control Signature Detected",
    "network_ids_exploit": "Suricata IDS Exploit Signature Detected",
    "network_ids_scan_recon": "Suricata IDS Scan or Recon Signature Detected",
    "network_ids_credential": "Suricata IDS Credential Attack Signature Detected",
    "network_ids_exfiltration": "Suricata IDS Exfiltration Signature Detected",
    "network_ids_policy": "Suricata IDS Policy Violation Signature Detected",
    "network_ids_protocol_anomaly": "Suricata IDS Protocol Anomaly Signature Detected",
    "network_ids_unknown_high": "Suricata IDS High-Severity Unknown Signature Detected",
}

IDS_ATTACK_TYPES = {
    "network_ids_malware": "IDS / Malware",
    "network_ids_c2": "IDS / Command and Control",
    "network_ids_exploit": "IDS / Exploit Attempt",
    "network_ids_scan_recon": "IDS / Scan or Recon",
    "network_ids_credential": "IDS / Credential Attack",
    "network_ids_exfiltration": "IDS / Exfiltration",
    "network_ids_policy": "IDS / Policy Violation",
    "network_ids_protocol_anomaly": "IDS / Protocol Anomaly",
    "network_ids_unknown_high": "IDS / Unknown High Severity",
}

NETWORK_RULE_EXPLANATIONS = {
    "network_port_scan": (
        "The rule counted unique destination ports reached by one source IP "
        "against the same destination IP."
    ),
    "network_internal_sweep": (
        "The rule counted unique destination IPs reached by one source IP "
        "on the same destination port."
    ),
    "network_suspicious_outbound": (
        "One suspicious outbound connection was enough to fire this rule."
    ),
    "network_c2_beaconing": (
        "Repeated flows from the same source to the same destination IP and "
        "destination port triggered this rule."
    ),
    "network_suspicious_dns": (
        "The rule counted suspicious DNS names queried by one source IP."
    ),
}

IDS_RULE_EXPLANATIONS = {
    "network_ids_malware": (
        "Suricata matched an IDS signature categorized as malware-related activity."
    ),
    "network_ids_c2": (
        "Suricata matched an IDS signature categorized as command-and-control activity."
    ),
    "network_ids_exploit": (
        "Suricata matched an IDS signature categorized as an exploit attempt."
    ),
    "network_ids_scan_recon": (
        "Suricata matched an IDS signature categorized as scan or reconnaissance activity."
    ),
    "network_ids_credential": (
        "Suricata matched an IDS signature categorized as credential attack activity."
    ),
    "network_ids_exfiltration": (
        "Suricata matched an IDS signature categorized as possible data exfiltration."
    ),
    "network_ids_policy": (
        "Suricata matched an IDS signature categorized as a policy violation."
    ),
    "network_ids_protocol_anomaly": (
        "Suricata matched an IDS signature categorized as a protocol anomaly."
    ),
    "network_ids_unknown_high": (
        "Suricata matched an IDS signature with unknown category but high or critical severity."
    ),
}

NETWORK_RULE_GROUP_BY = {
    "network_port_scan": "source_ip + destination_ip",
    "network_internal_sweep": "source_ip + destination_port",
    "network_suspicious_outbound": "source_ip + destination_ip + destination_port",
    "network_c2_beaconing": "source_ip + destination_ip + destination_port",
    "network_suspicious_dns": "source_ip",
}

IDS_RULE_GROUP_BY = {
    "network_ids_malware": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_c2": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_exploit": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_scan_recon": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_credential": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_exfiltration": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_policy": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_protocol_anomaly": "source_ip + destination_ip + destination_port + ids_rule_id",
    "network_ids_unknown_high": "source_ip + destination_ip + destination_port + ids_rule_id",
}


def _is_present(value: Any) -> bool:
    """
    Return True only for values safe to emit into structured alert documents.
    """
    if value is None:
        return False

    if isinstance(value, str):
        normalized = value.strip().lower()
        return bool(normalized) and normalized not in {"n/a", "none", "null", "unknown"}

    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)

    return True


def _is_network_rule(rule_id: str) -> bool:
    """
    Return True for custom network-layer rules supported by alert_builder.py.
    """
    return rule_id in NETWORK_RULE_IDS


def _is_ids_rule(rule_id: str) -> bool:
    """
    Return True for Suricata IDS category rules supported by alert_builder.py.
    """
    return rule_id in IDS_RULE_IDS


def _get_event_value(event: Event, attr_name: str) -> Any:
    """
    Safely read optional Event attributes without assuming every deployment
    has already rolled out the newest Event dataclass fields.
    """
    return getattr(event, attr_name, None)


def _set_nested_if_present(document: dict, path: tuple[str, ...], value: Any) -> None:
    """
    Set a nested dict value only when the value is meaningful.

    Prevents emitting None, empty strings, empty collections, "N/A", "none",
    "null", or "unknown" into structured ECS fields.
    """
    if not _is_present(value):
        return

    current = document
    for key in path[:-1]:
        current = current.setdefault(key, {})

    current[path[-1]] = value


def _normalize_user_name(value) -> Optional[str]:
    """
    Normalize a user value into a plain string or None.

    Handles:
      - str  → returned as-is if non-empty
      - dict → extracts ["name"] key
      - anything else → None

    This ensures user.name in the alert is ALWAYS a string.
    """
    if isinstance(value, dict):
        value = value.get("name")

    if isinstance(value, str) and value.strip():
        return value.strip()

    return None


def _extract_web_fields(raw_log: str) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Extract url.original, http.response.status_code, and user_agent.original
    from Nginx raw log strings.
    Expected format:
    client_ip - remote_user [timestamp] "method url_path HTTP/version" status_code response_bytes "referrer" "user_agent"
    """
    if not raw_log:
        return None, None, None

    url_original = None
    status_code = None
    user_agent = None

    try:
        parts = raw_log.split('"')
        if len(parts) >= 6:
            # parts[1] contains "METHOD /url HTTP/1.1"
            req_part = parts[1].strip()
            req_tokens = req_part.split(" ")
            if len(req_tokens) >= 2:
                url_original = req_tokens[1]

            # parts[2] contains " status_code response_bytes "
            status_part = parts[2].strip()
            status_tokens = status_part.split(" ")
            if len(status_tokens) >= 1:
                try:
                    status_code = int(status_tokens[0])
                except ValueError:
                    pass

            # parts[5] contains user_agent
            user_agent = parts[5].strip()
            if not user_agent or user_agent == "-":
                user_agent = None
    except Exception:
        pass

    return url_original, status_code, user_agent


def _sorted_string_list(value) -> List[str]:
    """
    Normalize list/set/tuple values into sorted unique strings.
    Drops None, empty strings, and 'unknown'.
    """
    if not value:
        return []

    try:
        return sorted(
            {
                str(v).strip()
                for v in value
                if v is not None
                and str(v).strip()
                and str(v).strip().lower() != "unknown"
            }
        )
    except TypeError:
        return []


def _slot_context_list(fired_slot, attr_name: str) -> List[str]:
    """
    Safely extract structured context from AccumulatorSlot.

    Supported attrs:
      - users_seen
      - source_ips_seen
      - hosts_seen
      - destination_ips_seen
    """
    return _sorted_string_list(getattr(fired_slot, attr_name, None))


def _cardinality_values(fired_slot) -> List[str]:
    """
    Extract unique cardinality values from AccumulatorSlot.events.

    Current accumulator cardinality tuples are expected to store the counted
    value at index 1 and the raw event at index 2.
    """
    return _sorted_string_list(
        e[1]
        for e in getattr(fired_slot, "events", [])
        if isinstance(e, (list, tuple)) and len(e) > 1
    )


def _latest_raw_event(raw_events: List[str], triggering_event: Event) -> Optional[str]:
    """
    Return the newest raw event available for helper extractors.
    """
    if raw_events:
        return raw_events[-1]

    raw_log = getattr(triggering_event, "raw_log", None)
    return raw_log if raw_log else None


def _apply_network_alert_fields(
    alert: dict,
    rule: RuleDefinition,
    fired_slot,
    triggering_event: Event,
    event_count: int,
    source_ips_seen: List[str],
    destination_ips_seen: List[str],
    first_seen: Optional[str],
    last_seen: Optional[str],
) -> None:
    """
    Add ECS-compatible network context, analyst evidence, and attack_context
    for supported custom network rules.

    This function only enriches the alert document. It does not evaluate rules,
    write alerts, create incidents, or parse raw logs.
    """
    rule_id = rule.rule_id

    source_port = _get_event_value(triggering_event, "source_port")
    destination_ip = _get_event_value(triggering_event, "destination_ip")
    destination_port = _get_event_value(triggering_event, "destination_port")
    network_transport = _get_event_value(triggering_event, "network_transport")
    network_protocol = _get_event_value(triggering_event, "network_protocol")
    network_bytes = _get_event_value(triggering_event, "network_bytes")
    network_packets = _get_event_value(triggering_event, "network_packets")
    dns_question_name = _get_event_value(triggering_event, "dns_question_name")
    event_dataset = _get_event_value(triggering_event, "event_dataset")
    event_action = _get_event_value(triggering_event, "event_type")
    event_tags = _sorted_string_list(_get_event_value(triggering_event, "tags"))

    alert.setdefault("alert", {})["title"] = NETWORK_RULE_TITLES[rule_id]

    _set_nested_if_present(alert, ("source", "ip"), triggering_event.source_ip)
    _set_nested_if_present(alert, ("source", "port"), source_port)
    _set_nested_if_present(alert, ("destination", "ip"), destination_ip)
    _set_nested_if_present(alert, ("destination", "port"), destination_port)
    _set_nested_if_present(alert, ("network", "transport"), network_transport)
    _set_nested_if_present(alert, ("network", "protocol"), network_protocol)
    _set_nested_if_present(alert, ("network", "bytes"), network_bytes)
    _set_nested_if_present(alert, ("network", "packets"), network_packets)
    _set_nested_if_present(alert, ("dns", "question", "name"), dns_question_name)
    _set_nested_if_present(alert, ("event", "dataset"), event_dataset)
    _set_nested_if_present(alert, ("event", "action"), event_action)

    if event_tags:
        alert["tags"] = sorted(set(alert.get("tags", [])) | set(event_tags))

    alert["evidence"]["event_count"] = event_count
    alert["evidence"]["rule_explanation"] = NETWORK_RULE_EXPLANATIONS[rule_id]
    alert["evidence"]["group_by"] = NETWORK_RULE_GROUP_BY[rule_id]

    if source_ips_seen:
        alert["evidence"]["source_ips_seen"] = source_ips_seen

    if destination_ips_seen:
        alert["evidence"]["destination_ips_seen"] = destination_ips_seen

    if first_seen:
        alert["evidence"]["first_seen"] = first_seen

    if last_seen:
        alert["evidence"]["last_seen"] = last_seen

    if rule.accumulator_type == "cardinality":
        cardinality_values = _cardinality_values(fired_slot)
        alert["evidence"]["cardinality_field"] = rule.cardinality_field

        if rule_id == "network_port_scan" and cardinality_values:
            alert["evidence"]["destination_ports_seen"] = cardinality_values

        elif rule_id == "network_internal_sweep" and cardinality_values:
            alert["evidence"]["destination_ips_seen"] = sorted(
                set(alert["evidence"].get("destination_ips_seen", []))
                | set(cardinality_values)
            )

        elif rule_id == "network_suspicious_dns" and cardinality_values:
            alert["evidence"]["dns_question_names_seen"] = cardinality_values

    attack_context = {
        "layer": "network",
        "rule_id": rule_id,
        "attack_type": rule_id,
        "group_key": fired_slot.group_key,
        "event_count": event_count,
        "time_window_seconds": rule.timeframe_seconds,
        "threshold": rule.threshold,
        "accumulator_type": rule.accumulator_type,
    }

    optional_attack_context = {
        "source_ip": triggering_event.source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "network_protocol": network_protocol,
        "network_transport": network_transport,
        "dns_question_name": dns_question_name,
        "cardinality_field": rule.cardinality_field,
        "reason": NETWORK_RULE_EXPLANATIONS[rule_id],
    }

    for key, value in optional_attack_context.items():
        if _is_present(value):
            attack_context[key] = value

    alert["attack_context"] = attack_context


def _apply_ids_alert_fields(
    alert: dict,
    rule: RuleDefinition,
    fired_slot,
    triggering_event: Event,
    event_count: int,
    source_ips_seen: List[str],
    destination_ips_seen: List[str],
    first_seen: Optional[str],
    last_seen: Optional[str],
) -> None:
    """
    Add Suricata IDS alert enrichment for IDS category rules.

    This function only uses structured Event fields populated by models.py.
    It does not parse raw logs, parse message strings, evaluate rules, write
    alerts, create incidents, or replace the SIEM-AI rule identity.
    """
    rule_id = rule.rule_id

    source_port = _get_event_value(triggering_event, "source_port")
    destination_ip = _get_event_value(triggering_event, "destination_ip")
    destination_port = _get_event_value(triggering_event, "destination_port")
    network_transport = _get_event_value(triggering_event, "network_transport")
    network_protocol = _get_event_value(triggering_event, "network_protocol")
    network_bytes = _get_event_value(triggering_event, "network_bytes")
    network_packets = _get_event_value(triggering_event, "network_packets")
    event_dataset = _get_event_value(triggering_event, "event_dataset")
    event_action = _get_event_value(triggering_event, "event_type")
    event_tags = _sorted_string_list(_get_event_value(triggering_event, "tags"))

    ids_rule_id = _get_event_value(triggering_event, "ids_rule_id")
    ids_rule_name = _get_event_value(triggering_event, "ids_rule_name")
    ids_rule_category = _get_event_value(triggering_event, "ids_rule_category")
    ids_severity = _get_event_value(triggering_event, "ids_severity")
    ids_severity_label = _get_event_value(triggering_event, "ids_severity_label")
    ids_alert_action = _get_event_value(triggering_event, "ids_alert_action")
    ids_alert_signature = _get_event_value(triggering_event, "ids_alert_signature")
    ids_alert_category = _get_event_value(triggering_event, "ids_alert_category")
    ids_alert_gid = _get_event_value(triggering_event, "ids_alert_gid")
    ids_alert_rev = _get_event_value(triggering_event, "ids_alert_rev")

    alert.setdefault("alert", {})["title"] = IDS_RULE_TITLES[rule_id]

    # ECS/network evidence.
    _set_nested_if_present(alert, ("source", "ip"), triggering_event.source_ip)
    _set_nested_if_present(alert, ("source", "port"), source_port)
    _set_nested_if_present(alert, ("destination", "ip"), destination_ip)
    _set_nested_if_present(alert, ("destination", "port"), destination_port)
    _set_nested_if_present(alert, ("network", "transport"), network_transport)
    _set_nested_if_present(alert, ("network", "protocol"), network_protocol)
    _set_nested_if_present(alert, ("network", "bytes"), network_bytes)
    _set_nested_if_present(alert, ("network", "packets"), network_packets)
    _set_nested_if_present(alert, ("event", "dataset"), event_dataset)
    _set_nested_if_present(alert, ("event", "action"), event_action)
    _set_nested_if_present(alert, ("event", "severity"), ids_severity)

    # Keep SIEM-AI rule.id untouched. Store Suricata IDS signature metadata
    # separately under ids.*, suricata.alert.*, evidence, and attack_context.
    _set_nested_if_present(alert, ("ids", "rule_id"), ids_rule_id)
    _set_nested_if_present(alert, ("ids", "rule_name"), ids_rule_name)
    _set_nested_if_present(alert, ("ids", "rule_category"), ids_rule_category)
    _set_nested_if_present(alert, ("ids", "severity"), ids_severity)
    _set_nested_if_present(alert, ("ids", "severity_label"), ids_severity_label)
    _set_nested_if_present(alert, ("ids", "alert_action"), ids_alert_action)

    _set_nested_if_present(alert, ("suricata", "alert", "signature"), ids_alert_signature)
    _set_nested_if_present(alert, ("suricata", "alert", "category"), ids_alert_category)
    _set_nested_if_present(alert, ("suricata", "alert", "action"), ids_alert_action)
    _set_nested_if_present(alert, ("suricata", "alert", "signature_id"), ids_rule_id)
    _set_nested_if_present(alert, ("suricata", "alert", "gid"), ids_alert_gid)
    _set_nested_if_present(alert, ("suricata", "alert", "rev"), ids_alert_rev)

    if event_tags:
        alert["tags"] = sorted(set(alert.get("tags", [])) | set(event_tags))

    alert["evidence"]["event_count"] = event_count
    alert["evidence"]["rule_explanation"] = IDS_RULE_EXPLANATIONS[rule_id]
    alert["evidence"]["group_by"] = IDS_RULE_GROUP_BY[rule_id]
    alert["evidence"]["source"] = "suricata_ids"

    optional_evidence = {
        "ids_rule_id": ids_rule_id,
        "ids_rule_name": ids_rule_name,
        "ids_rule_category": ids_rule_category,
        "ids_severity": ids_severity,
        "ids_severity_label": ids_severity_label,
        "ids_alert_action": ids_alert_action,
        "ids_alert_signature": ids_alert_signature,
        "ids_alert_category": ids_alert_category,
        "ids_alert_gid": ids_alert_gid,
        "ids_alert_rev": ids_alert_rev,
    }

    for key, value in optional_evidence.items():
        if _is_present(value):
            alert["evidence"][key] = value

    if source_ips_seen:
        alert["evidence"]["source_ips_seen"] = source_ips_seen

    if destination_ips_seen:
        alert["evidence"]["destination_ips_seen"] = destination_ips_seen

    if first_seen:
        alert["evidence"]["first_seen"] = first_seen

    if last_seen:
        alert["evidence"]["last_seen"] = last_seen

    attack_context = {
        "layer": "network",
        "source": "suricata_ids",
        "rule_id": rule_id,
        "attack_type": IDS_ATTACK_TYPES[rule_id],
        "group_key": fired_slot.group_key,
        "event_count": event_count,
        "time_window_seconds": rule.timeframe_seconds,
        "threshold": rule.threshold,
        "accumulator_type": rule.accumulator_type,
    }

    optional_attack_context = {
        "ids_rule_id": ids_rule_id,
        "ids_rule_name": ids_rule_name,
        "ids_rule_category": ids_rule_category,
        "ids_severity": ids_severity,
        "ids_severity_label": ids_severity_label,
        "ids_alert_action": ids_alert_action,
        "ids_alert_signature": ids_alert_signature,
        "ids_alert_category": ids_alert_category,
        "ids_alert_gid": ids_alert_gid,
        "ids_alert_rev": ids_alert_rev,
        "source_ip": triggering_event.source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "network_transport": network_transport,
        "network_protocol": network_protocol,
        "tags": event_tags,
        "reason": IDS_RULE_EXPLANATIONS[rule_id],
    }

    for key, value in optional_attack_context.items():
        if _is_present(value):
            attack_context[key] = value

    alert["attack_context"] = attack_context


def build_alert(
    rule: RuleDefinition,
    fired_slot,
    triggering_event: Event,
    watch_entry: Optional[dict] = None,
) -> dict:
    """
    Build a complete, type-safe alert document using ECS-compatible fields.

    fired_slot:
        AccumulatorSlot with:
          - events
          - group_key
          - suppressed_until
          - users_seen
          - source_ips_seen
          - hosts_seen
          - destination_ips_seen

    watch_entry:
        dict for success_after_brute_force correlation context.

    Returns:
        dict safe for Elasticsearch indexing.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # ── Extract evidence from fired slot ──────────────────────────────────
    matched_event_ids: List[str] = []
    raw_events: List[str] = []
    event_count = 0

    if rule.accumulator_type == "frequency":
        raw_events = [e[1] for e in fired_slot.events[-10:]]
        event_count = len(fired_slot.events)

    elif rule.accumulator_type == "cardinality":
        raw_events = [e[2] for e in fired_slot.events[-10:]]
        event_count = len(fired_slot.events)

    else:
        # watchlist / success_after_brute_force
        raw_events = [triggering_event.raw_log] if triggering_event.raw_log else []
        event_count = 1

    # ── Structured slot context ───────────────────────────────────────────
    users_seen = _slot_context_list(fired_slot, "users_seen")
    source_ips_seen = _slot_context_list(fired_slot, "source_ips_seen")
    hosts_seen = _slot_context_list(fired_slot, "hosts_seen")
    destination_ips_seen = _slot_context_list(fired_slot, "destination_ips_seen")

    if triggering_event.user and triggering_event.user not in users_seen:
        users_seen.append(triggering_event.user)
        users_seen = sorted(set(users_seen))

    if triggering_event.source_ip and triggering_event.source_ip not in source_ips_seen:
        source_ips_seen.append(triggering_event.source_ip)
        source_ips_seen = sorted(set(source_ips_seen))

    if triggering_event.host and triggering_event.host not in hosts_seen:
        hosts_seen.append(triggering_event.host)
        hosts_seen = sorted(set(hosts_seen))

    destination_ip = _get_event_value(triggering_event, "destination_ip")
    if destination_ip and destination_ip not in destination_ips_seen:
        destination_ips_seen.append(str(destination_ip))
        destination_ips_seen = sorted(set(destination_ips_seen))

    # ── Extract unique values for cardinality rules ───────────────────────
    unique_users: Optional[List[str]] = None
    unique_ips: Optional[List[str]] = None

    if rule.accumulator_type == "cardinality":
        if rule.cardinality_field == "user":
            unique_users = sorted({str(e[1]) for e in fired_slot.events if e[1]})
            users_seen = sorted(set(users_seen) | set(unique_users))

        elif rule.cardinality_field == "source_ip":
            unique_ips = sorted({str(e[1]) for e in fired_slot.events if e[1]})
            source_ips_seen = sorted(set(source_ips_seen) | set(unique_ips))

    # ── Time span from evidence ───────────────────────────────────────────
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    if fired_slot.events:
        timestamps = [e[0] for e in fired_slot.events]

        first_seen = datetime.utcfromtimestamp(min(timestamps)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        last_seen = datetime.utcfromtimestamp(max(timestamps)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )

    # ── Suppressed_until: ISO8601 or omitted ──────────────────────────────
    suppressed_until: Optional[str] = None

    if (
        hasattr(fired_slot, "suppressed_until")
        and fired_slot.suppressed_until
        and fired_slot.suppressed_until > 0
    ):
        suppressed_until = datetime.utcfromtimestamp(
            fired_slot.suppressed_until
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # ── Description ───────────────────────────────────────────────────────
    description = _build_description(
        rule=rule,
        event=triggering_event,
        count=event_count,
        unique_users=unique_users,
        unique_ips=unique_ips,
        watch_entry=watch_entry,
    )

    alert_id = f"alert-{uuid.uuid4().hex}"

    # ── Build alert document ──────────────────────────────────────────────
    alert: dict = {
        "@timestamp": now_iso,
        "alert": {
            "id": alert_id,
        },
        "rule": {
            "id": rule.rule_id,
            "name": rule.rule_id,
            "severity": rule.severity,
            "description": description,
        },
        "event": {
            "count": event_count,
        },
        "matched": {
            "event_ids": matched_event_ids,
        },
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
        },
        "evidence": {
            "raw_events": raw_events,
            "group_key": fired_slot.group_key,
            "window_seconds": rule.timeframe_seconds,
        },
        "mitre": {
            "id": rule.mitre_id,
            "tactic": rule.mitre_tactic,
            "technique": rule.mitre_technique,
        },
    }

    # ── ECS / event fields ────────────────────────────────────────────────
    if triggering_event.source_ip:
        alert["source"] = {"ip": triggering_event.source_ip}

    user_name = _normalize_user_name(triggering_event.user)
    if user_name:
        alert["user.name"] = user_name

    if triggering_event.host:
        alert["host"] = {"name": triggering_event.host}

    # ── Web Fields ────────────────────────────────────────────────────────
    if rule.rule_id.startswith("web_"):
        alert["process"] = {"name": "nginx"}

        # We need to extract web fields. Best to use the last event's raw log.
        latest_raw_log = _latest_raw_event(raw_events, triggering_event)
        url_original, status_code, user_agent = _extract_web_fields(latest_raw_log or "")

        if url_original:
            alert.setdefault("url", {})["original"] = url_original
        if status_code is not None:
            alert.setdefault("http", {}).setdefault("response", {})[
                "status_code"
            ] = status_code
        if user_agent:
            alert.setdefault("user_agent", {})["original"] = user_agent

        # Tags for web rules
        tags = alert.get("tags", [])
        if "web_attack" not in tags:
            tags.append("web_attack")

        # Add ready_for_detection if suspicious (not 404 scanning)
        if rule.rule_id != "web_404_scanning" and "ready_for_detection" not in tags:
            tags.append("ready_for_detection")

        if tags:
            alert["tags"] = tags

    if _is_network_rule(rule.rule_id):
        _apply_network_alert_fields(
            alert=alert,
            rule=rule,
            fired_slot=fired_slot,
            triggering_event=triggering_event,
            event_count=event_count,
            source_ips_seen=source_ips_seen,
            destination_ips_seen=destination_ips_seen,
            first_seen=first_seen,
            last_seen=last_seen,
        )

    if _is_ids_rule(rule.rule_id):
        _apply_ids_alert_fields(
            alert=alert,
            rule=rule,
            fired_slot=fired_slot,
            triggering_event=triggering_event,
            event_count=event_count,
            source_ips_seen=source_ips_seen,
            destination_ips_seen=destination_ips_seen,
            first_seen=first_seen,
            last_seen=last_seen,
        )

    # ── Optional timing fields ────────────────────────────────────────────
    if suppressed_until is not None:
        alert["suppressed_until"] = suppressed_until

    if first_seen:
        alert["evidence"]["first_seen"] = first_seen

    if last_seen:
        alert["evidence"]["last_seen"] = last_seen

    # ── Structured evidence context ───────────────────────────────────────
    if users_seen:
        alert["evidence"]["users_seen"] = users_seen

    if source_ips_seen:
        alert["evidence"]["source_ips_seen"] = source_ips_seen

    if hosts_seen:
        alert["evidence"]["hosts_seen"] = hosts_seen

    if unique_users is not None:
        alert["evidence"]["unique_users"] = unique_users

    if unique_ips is not None:
        alert["evidence"]["unique_ips"] = unique_ips

    if (_is_network_rule(rule.rule_id) or _is_ids_rule(rule.rule_id)) and destination_ips_seen:
        alert["evidence"]["destination_ips_seen"] = destination_ips_seen

    # ── Correlation context: success_after_brute_force only ───────────────
    if watch_entry:
        correlation_users = _sorted_string_list(watch_entry.get("users_seen"))
        correlation_ips = _sorted_string_list(watch_entry.get("source_ips"))
        correlation_host = watch_entry.get("host")
        correlation_strategy = watch_entry.get(
            "correlation_strategy",
            watch_entry.get("strategy", "identity_user_host"),
        )

        parent_rule = watch_entry.get("parent_rule")
        targeted_user = watch_entry.get("targeted_user")
        failed_count = watch_entry.get("failed_count")

        alert["correlation"] = {
            "parent_rule": parent_rule,
            "strategy": correlation_strategy,
            "reason": (
                f"Successful login as '{triggering_event.user}' on host "
                f"'{triggering_event.host}' after recent {parent_rule} activity"
            ),
        }

        if targeted_user:
            alert["correlation"]["targeted_user"] = targeted_user

        if correlation_users:
            alert["correlation"]["users_seen"] = correlation_users
            alert["evidence"]["users_seen"] = sorted(
                set(alert["evidence"].get("users_seen", [])) | set(correlation_users)
            )

        if correlation_ips:
            alert["correlation"]["source_ips"] = correlation_ips
            alert["evidence"]["source_ips_seen"] = sorted(
                set(alert["evidence"].get("source_ips_seen", [])) | set(correlation_ips)
            )

        if correlation_host:
            alert["correlation"]["host"] = correlation_host
            alert["evidence"]["hosts_seen"] = sorted(
                set(alert["evidence"].get("hosts_seen", [])) | {str(correlation_host)}
            )

        if failed_count is not None:
            alert["correlation"]["brute_force_attempt_count"] = failed_count

    log.info("Alert built: [%s] %s", rule.severity, rule.rule_id)
    return alert


# ── Description builder ───────────────────────────────────────────────────────

def _build_description(
    rule: RuleDefinition,
    event: Event,
    count: int,
    unique_users: Optional[List[str]],
    unique_ips: Optional[List[str]],
    watch_entry: Optional[dict],
) -> str:
    if rule.rule_id == "ssh_bruteforce":
        return (
            f"SSH brute force: {count} failed logins from "
            f"{event.source_ip} against host '{event.host}' "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "user_bruteforce_by_user":
        return (
            f"Targeted brute force: {count} failed attempts against user "
            f"'{event.user}' from {event.source_ip} on host '{event.host}' "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "password_spray":
        users_str = ", ".join(unique_users[:5]) if unique_users else "unknown"
        n_users = len(unique_users) if unique_users else 0

        return (
            f"Password spray: {event.source_ip} attempted {n_users} usernames "
            f"on host '{event.host}' ({users_str}) "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "distributed_bruteforce":
        ips_str = ", ".join(unique_ips[:3]) if unique_ips else "unknown"
        n_ips = len(unique_ips) if unique_ips else 0

        return (
            f"Distributed brute force: {n_ips} IPs ({ips_str}) attacking user "
            f"'{event.user}' on host '{event.host}' "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "success_after_brute_force":
        parent = watch_entry.get("parent_rule", "unknown") if watch_entry else "unknown"
        target = watch_entry.get("targeted_user", event.user) if watch_entry else event.user
        strategy = (
            watch_entry.get("correlation_strategy", "identity_user_host")
            if watch_entry
            else "identity_user_host"
        )

        return (
            f"ACCOUNT COMPROMISE: successful login as '{event.user}' "
            f"from {event.source_ip} on host '{event.host}' after {parent} alert. "
            f"Previous target: '{target}'. Correlation: {strategy}"
        )

    if rule.rule_id == "sudo_bruteforce":
        return (
            f"Sudo brute force: {count} failed sudo attempts by user "
            f"'{event.user}' on host '{event.host}' "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "web_path_traversal":
        return (
            f"Web Path Traversal: {count} attempts from {event.source_ip} "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "web_sql_injection":
        return (
            f"Web SQL Injection: {count} attempts from {event.source_ip} "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "web_xss":
        return f"Web XSS: {count} attempts from {event.source_ip} in {rule.timeframe_seconds}s"

    if rule.rule_id == "web_sensitive_file":
        return (
            f"Web Sensitive File Probe: {count} attempts from {event.source_ip} "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "web_404_scanning":
        return (
            f"Web 404 Scanning: {count} 404 responses from {event.source_ip} "
            f"in {rule.timeframe_seconds}s"
        )

    if rule.rule_id == "network_port_scan":
        return (
            "One source IP connected to many destination ports on the same target "
            f"within {rule.timeframe_seconds}s."
        )

    if rule.rule_id == "network_internal_sweep":
        return (
            "One source IP connected to many destination hosts on the same "
            f"destination port within {rule.timeframe_seconds}s."
        )

    if rule.rule_id == "network_suspicious_outbound":
        return "An internal host connected to a suspicious outbound destination port."

    if rule.rule_id == "network_c2_beaconing":
        return (
            "A host repeatedly connected to the same destination IP and port, "
            "indicating possible beaconing behavior."
        )

    if rule.rule_id == "network_suspicious_dns":
        return (
            "A host queried multiple suspicious DNS names within "
            f"{rule.timeframe_seconds}s."
        )

    if rule.rule_id in IDS_RULE_IDS:
        ids_rule_name = _get_event_value(event, "ids_rule_name")
        attack_type = IDS_ATTACK_TYPES.get(rule.rule_id, rule.rule_id)

        if _is_present(ids_rule_name):
            return (
                f"{attack_type}: Suricata matched IDS signature "
                f"'{ids_rule_name}'. The alert was normalized by Logstash "
                "and routed by SIEM-AI based on IDS category tags."
            )

        return (
            f"{attack_type}: Suricata matched an IDS signature. The alert was "
            "normalized by Logstash and routed by SIEM-AI based on IDS category tags."
        )

    return f"{rule.rule_id}: threshold {count}/{rule.threshold} crossed"