"""
detection_engine/lifecycle_contract.py

THE SINGLE LIFECYCLE CONTRACT FOR ABUR-SIEM.

Rules:
  - OPEN   = active security signal. Alert exists and has not been dismissed.
  - CLOSED = admin has reviewed and dismissed the alert.

Allowed transitions (ADMIN ONLY via API):
  OPEN   → CLOSED
  CLOSED → OPEN

Forbidden:
  - AI layers may NOT change status.
  - Engines (rule_engine, incident_engine) may NOT change alert status.
  - alert_writer may NOT change status after initial creation.
  - Incident status is NEVER written directly.
    It is ALWAYS computed from the statuses of its linked alerts:
      any linked alert OPEN  → incident OPEN
      all linked alerts CLOSED → incident CLOSED

This file is the authoritative reference. Any code that wants to touch
lifecycle fields must import from here and follow these rules.
"""

from __future__ import annotations

ALERT_STATUS_OPEN   = "OPEN"
ALERT_STATUS_CLOSED = "CLOSED"

ALLOWED_ALERT_STATUSES = {ALERT_STATUS_OPEN, ALERT_STATUS_CLOSED}
# Correlation window default — alerts older than this are ineligible for correlation
DEFAULT_CORRELATION_WINDOW_SECONDS = 7200  # 2 hours

# Incident silence threshold — incident freezes after this many seconds of no new alerts
INCIDENT_SILENCE_THRESHOLD_SECONDS = 1800  # 30 minutes

INCIDENT_LIFECYCLE_ACTIVE = "active"
INCIDENT_LIFECYCLE_FROZEN = "frozen"
INCIDENT_LIFECYCLE_CLOSED = "closed"

INCIDENT_STATUS_OPEN   = "open"
INCIDENT_STATUS_CLOSED = "closed"

ALLOWED_TRANSITIONS = {
    ALERT_STATUS_OPEN:   {ALERT_STATUS_CLOSED},
    ALERT_STATUS_CLOSED: {ALERT_STATUS_OPEN},
}


def is_valid_transition(current: str, requested: str) -> bool:
    """Return True if the requested status transition is allowed."""
    return requested in ALLOWED_TRANSITIONS.get(current.upper(), set())


def derive_incident_status(alert_statuses: list[str]) -> str:
    """
    Compute incident status from the statuses of all linked alerts.

    Rules (Wazuh-equivalent active-response derivation):
      - Empty list           → OPEN  (incident just created, no alerts synced yet)
      - Any alert is OPEN    → OPEN
      - All alerts CLOSED    → CLOSED
    """
    if not alert_statuses:
        return INCIDENT_STATUS_OPEN

    normalized = [s.upper() for s in alert_statuses]

    if any(s == ALERT_STATUS_OPEN for s in normalized):
        return INCIDENT_STATUS_OPEN

    if all(s == ALERT_STATUS_CLOSED for s in normalized):
        return INCIDENT_STATUS_CLOSED

    return INCIDENT_STATUS_OPEN