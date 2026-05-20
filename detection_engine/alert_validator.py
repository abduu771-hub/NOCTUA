"""
detection_engine/alert_validator.py
Validates alert documents before they are sent to Elasticsearch.

If validation fails:
  - the alert is NOT sent to ES
  - the validation error is logged
  - the failed alert is written to logs/invalid_alerts.jsonl

Never raises — returns (is_valid, error_message).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from datetime import datetime
from typing import Optional, Tuple

from . import config

log = logging.getLogger("detection_engine.alert_validator")

INVALID_ALERTS_LOG = os.path.join(config.LOG_DIR, "invalid_alerts.jsonl")

# Values that must NEVER appear in structured fields
_FORBIDDEN_VALUES = frozenset({"N/A", "", "none", "null", "n/a", "None", "NULL"})


def _deep_get(d: dict, dotted_key: str, default=None):
    keys = dotted_key.split(".")
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is default:
            return default
    return d


def _is_valid_iso8601(value: str) -> bool:
    """Check if a string is a parseable ISO8601 timestamp."""
    if not value or value in _FORBIDDEN_VALUES:
        return False
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        datetime.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False


def _is_valid_ip(value: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def validate_alert(alert: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate an alert document against the siem-alerts schema.

    Returns (True, None) if valid.
    Returns (False, error_message) if invalid.
    """
    errors: list[str] = []

    # ── @timestamp — required, valid ISO8601 ──────────────────────────────
    ts = alert.get("@timestamp")
    if not ts:
        errors.append("missing @timestamp")
    elif isinstance(ts, str) and not _is_valid_iso8601(ts):
        errors.append(f"invalid @timestamp: {ts!r}")

    # ── rule.id — required ────────────────────────────────────────────────
    rule_id = _deep_get(alert, "rule.id")
    if not rule_id:
        errors.append("missing rule.id")

    # ── rule.name — required ──────────────────────────────────────────────
    rule_name = _deep_get(alert, "rule.name")
    if not rule_name:
        errors.append("missing rule.name")

    # ── rule.severity — required ──────────────────────────────────────────
    rule_sev = _deep_get(alert, "rule.severity")
    if not rule_sev:
        errors.append("missing rule.severity")

    # ── event.count — required integer ────────────────────────────────────
    event_count = _deep_get(alert, "event.count")
    if event_count is None:
        errors.append("missing event.count")
    elif not isinstance(event_count, int):
        errors.append(f"event.count must be int, got {type(event_count).__name__}")

    # ── matched.event_ids — required list ─────────────────────────────────
    event_ids = _deep_get(alert, "matched.event_ids")
    if event_ids is None:
        errors.append("missing matched.event_ids")
    elif not isinstance(event_ids, list):
        errors.append(f"matched.event_ids must be list, got {type(event_ids).__name__}")

    # ── suppressed_until — if present, must be valid ISO8601 or None ──────
    sup = alert.get("suppressed_until")
    if sup is not None:
        if isinstance(sup, str):
            if sup in _FORBIDDEN_VALUES:
                errors.append(f"suppressed_until has forbidden value: {sup!r}")
            elif not _is_valid_iso8601(sup):
                errors.append(f"suppressed_until is not valid ISO8601: {sup!r}")

    # ── user — if present, must be {"name": "<string>"}, never a bare string ─
    user_field = alert.get("user")
    if user_field is not None:
        if isinstance(user_field, str):
            errors.append(
                f"user must be an object with 'name' key, got bare string: {user_field!r}"
            )
        elif isinstance(user_field, dict):
            uname = user_field.get("name")
            if uname is None:
                errors.append("user object is missing required 'name' key")
            elif not isinstance(uname, str) or not uname.strip():
                errors.append(f"user.name must be a non-empty string, got: {uname!r}")
        else:
            errors.append(f"user must be an object, got {type(user_field).__name__}")

    # ── source.ip — if present, must be valid IP or None ──────────────────
    src_ip = _deep_get(alert, "source.ip")
    if src_ip is not None:
        if isinstance(src_ip, str) and src_ip in _FORBIDDEN_VALUES:
            errors.append(f"source.ip has forbidden value: {src_ip!r}")
        elif isinstance(src_ip, str) and not _is_valid_ip(src_ip):
            errors.append(f"source.ip is not a valid IP: {src_ip!r}")

    # ── Scan all string values for forbidden placeholders ─────────────────
    _scan_forbidden(alert, "", errors)

    if errors:
        error_msg = "; ".join(errors)
        log.error("Alert validation failed: %s", error_msg)
        _write_invalid(alert, error_msg)
        return False, error_msg

    return True, None


def _scan_forbidden(obj, path: str, errors: list) -> None:
    """Recursively scan for forbidden placeholder values in string fields."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            _scan_forbidden(v, f"{path}.{k}" if path else k, errors)
    elif isinstance(obj, str) and obj in _FORBIDDEN_VALUES:
        errors.append(f"forbidden value {obj!r} at {path}")


def _write_invalid(alert: dict, error: str) -> None:
    """Append invalid alert to the invalid alerts log."""
    try:
        os.makedirs(os.path.dirname(INVALID_ALERTS_LOG) or ".", exist_ok=True)
        with open(INVALID_ALERTS_LOG, "a") as f:
            record = {"error": error, "alert": alert}
            f.write(json.dumps(record, default=str) + "\n")
            f.flush()
    except Exception:
        pass
