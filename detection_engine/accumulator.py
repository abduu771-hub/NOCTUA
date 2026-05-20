"""
detection_engine/accumulator.py
Sliding-window accumulator for frequency and cardinality rules.

Implements sliding (NOT tumbling) windows.
Handles suppression after alert firing to prevent alert storms.

MUST NOT trigger alerts — it only tracks state and reports when
thresholds are crossed. The caller decides what to do.

Permanent context model:
  - events              → evidence used for thresholding
  - users_seen          → all users observed in this slot/window
  - source_ips_seen     → all source IPs observed in this slot/window
  - hosts_seen          → all hosts observed in this slot/window

This allows rule_engine.py to build success-after-brute-force correlation
using user.name + host.name without depending on same source.ip.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .models import Event
from .rules import RuleDefinition


@dataclass
class AccumulatorSlot:
    rule_id: str
    group_key: str

    # For FREQUENCY:   [(timestamp_float, raw_log), ...]
    # For CARDINALITY: [(timestamp_float, field_value, raw_log), ...]
    events: List[Tuple] = field(default_factory=list)

    # Structured context for permanent correlation.
    users_seen: Set[str] = field(default_factory=set)
    source_ips_seen: Set[str] = field(default_factory=set)
    hosts_seen: Set[str] = field(default_factory=set)
    destination_ips_seen: Set[str] = field(default_factory=set)

    # Unix timestamp. While time.time() < suppressed_until → do NOT fire.
    suppressed_until: float = 0.0


class AccumulatorManager:
    """
    Central accumulator for all rules.

    Key concept:
        Each (rule_id, group_key) pair gets its own AccumulatorSlot.
        The slot holds timestamped evidence and implements the sliding window.
    """

    def __init__(self) -> None:
        # Key: (rule_id, group_key) → AccumulatorSlot
        self._slots: Dict[Tuple[str, str], AccumulatorSlot] = {}
        self._last_cleanup = time.time()

    # ── Public API ────────────────────────────────────────────────────────

    def process(self, event: Event, rule: RuleDefinition) -> Optional[AccumulatorSlot]:
        """
        Process one event against one rule.

        Returns a COPY of the slot if the rule FIRED, else None.
        """
        group_key = self._build_group_key(event, rule)
        if group_key is None:
            return None

        slot_key = (rule.rule_id, group_key)

        if slot_key not in self._slots:
            self._slots[slot_key] = AccumulatorSlot(
                rule_id=rule.rule_id,
                group_key=group_key,
            )

        slot = self._slots[slot_key]

        now = time.time()

        # Suppression check BEFORE adding event.
        if now < slot.suppressed_until:
            return None

        # Add structured context first.
        self._add_context(slot, event)

        # Add threshold evidence.
        if rule.accumulator_type == "frequency":
            slot.events.append(
                (
                    event.timestamp.timestamp(),
                    event.raw_log,
                )
            )

        elif rule.accumulator_type == "cardinality":
            field_value = self._get_cardinality_field(event, rule.cardinality_field)
            if field_value is None:
                return None

            existing_values = {e[1] for e in slot.events}

            if field_value not in existing_values:
                slot.events.append(
                    (
                        event.timestamp.timestamp(),
                        field_value,
                        event.raw_log,
                    )
                )

        else:
            # Watchlist rules are handled by rule_engine.py, not here.
            return None

        # Sliding window eviction.
        cutoff = now - rule.timeframe_seconds
        slot.events = [e for e in slot.events if e[0] >= cutoff]

        # Rebuild context from the surviving evidence when possible.
        # For full correctness across sliding windows, context is rebuilt from
        # current event stream evidence. Cardinality rules preserve field values;
        # frequency rules keep current context until fire/reset.
        self._prune_context_if_possible(slot, rule)

        # Threshold evaluation.
        fired = False

        if rule.accumulator_type == "frequency":
            fired = len(slot.events) >= rule.threshold

        elif rule.accumulator_type == "cardinality":
            unique_values = {e[1] for e in slot.events}
            fired = len(unique_values) >= rule.threshold

        if not fired:
            return None

        # Suppress and return snapshot.
        slot.suppressed_until = now + rule.ignore_seconds

        fired_slot = AccumulatorSlot(
            rule_id=slot.rule_id,
            group_key=slot.group_key,
            events=list(slot.events),
            users_seen=set(slot.users_seen),
            source_ips_seen=set(slot.source_ips_seen),
            hosts_seen=set(slot.hosts_seen),
            destination_ips_seen=set(slot.destination_ips_seen),
            suppressed_until=slot.suppressed_until,
        )

        # Reset evidence/context after firing to prevent duplicate alerts.
        slot.events.clear()
        slot.users_seen.clear()
        slot.source_ips_seen.clear()
        slot.hosts_seen.clear()
        slot.destination_ips_seen.clear()

        return fired_slot

    def cleanup(self) -> None:
        """
        Remove stale slots.

        Call this periodically from RuleEngine.cleanup().
        """
        now = time.time()

        if now - self._last_cleanup < 60:
            return

        to_delete = [
            key
            for key, slot in self._slots.items()
            if not slot.events
            and not slot.users_seen
            and not slot.source_ips_seen
            and not slot.hosts_seen
            and not slot.destination_ips_seen
            and slot.suppressed_until < now
        ]

        for key in to_delete:
            del self._slots[key]

        self._last_cleanup = now

    def get_snapshot(self) -> dict:
        """Serializable state for diagnostics / persistence."""
        return {
            str(k): {
                "rule_id": v.rule_id,
                "group_key": v.group_key,
                "suppressed_until": v.suppressed_until,
                "event_count": len(v.events),
                "users_seen": sorted(v.users_seen),
                "source_ips_seen": sorted(v.source_ips_seen),
                "hosts_seen": sorted(v.hosts_seen),
                "destination_ips_seen": sorted(v.destination_ips_seen),
            }
            for k, v in self._slots.items()
        }

    # ── Internal helpers ──────────────────────────────────────────────────

    def _add_context(self, slot: AccumulatorSlot, event: Event) -> None:
        if event.user:
            slot.users_seen.add(event.user)

        if event.source_ip:
            slot.source_ips_seen.add(event.source_ip)

        if event.host:
            slot.hosts_seen.add(event.host)

        if event.destination_ip:
            slot.destination_ips_seen.add(event.destination_ip)

    def _prune_context_if_possible(
        self,
        slot: AccumulatorSlot,
        rule: RuleDefinition,
    ) -> None:
        """
        Keep context aligned with current evidence when the rule structure
        allows it.

        For cardinality rules:
          - password_spray with cardinality_field="user" can rebuild users_seen.
          - distributed_bruteforce with cardinality_field="source_ip" can rebuild source_ips_seen.

        Frequency rules keep context until the slot fires/reset because the
        event tuple only stores raw_log, not full structured fields.
        """
        if rule.accumulator_type != "cardinality":
            return

        if rule.cardinality_field == "user":
            slot.users_seen = {str(e[1]) for e in slot.events if e[1]}

        elif rule.cardinality_field == "source_ip":
            slot.source_ips_seen = {str(e[1]) for e in slot.events if e[1]}

        elif rule.cardinality_field == "destination_ip":
            slot.destination_ips_seen = {str(e[1]) for e in slot.events if e[1]}

    def _build_group_key(self, event: Event, rule: RuleDefinition) -> Optional[str]:
        """
        Build a stable group key for each rule.

        Permanent grouping model:
          - ssh_bruteforce          → source.ip + host.name
          - user_bruteforce_by_user → source.ip + user.name + host.name
          - password_spray          → source.ip + host.name
          - distributed_bruteforce  → user.name + host.name

        This prevents unrelated hosts from being merged into the same detection.
        """
        rule_id = rule.rule_id

        if rule_id == "ssh_bruteforce":
            src_ip = event.source_ip
            host = event.host

            if not src_ip or not host:
                return None

            return f"ip::{src_ip}::host::{host}"

        if rule_id == "user_bruteforce_by_user":
            src_ip = event.source_ip
            user = event.user
            host = event.host

            if not src_ip or not user or not host:
                return None

            return f"ip::{src_ip}::user::{user}::host::{host}"

        if rule_id == "password_spray":
            src_ip = event.source_ip
            host = event.host

            if not src_ip or not host:
                return None

            return f"ip::{src_ip}::host::{host}"

        if rule_id == "distributed_bruteforce":
            user = event.user
            host = event.host

            if not user or not host:
                return None

            return f"user::{user}::host::{host}"

        if rule_id.startswith("web_"):
            src_ip = event.source_ip
            host = event.host

            if not src_ip or not host:
                return None

            return f"ip::{src_ip}::host::{host}"

        if rule_id.startswith("network_"):
            parts: List[str] = []
            for field_name in rule.group_by_fields:
                value = getattr(event, field_name, None)
                if value is None:
                    return None
                parts.append(f"{field_name}={value}")
            return "|".join(parts)

        # Default fallback for any other rule types.
        parts: List[str] = []

        for field_name in rule.group_by_fields:
            value = getattr(event, field_name, None)

            if value is None:
                return None

            parts.append(str(value))

        return "::".join(parts)

    @staticmethod
    def _get_cardinality_field(
        event: Event,
        field_name: Optional[str],
    ) -> Optional[str]:
        if field_name is None:
            return None

        if field_name == "url_original":
            # Extract url from Nginx raw log string
            raw_log = event.raw_log
            if raw_log:
                try:
                    parts = raw_log.split('"')
                    if len(parts) >= 6:
                        req_part = parts[1].strip()
                        req_tokens = req_part.split(' ')
                        if len(req_tokens) >= 2:
                            return req_tokens[1]
                except Exception:
                    pass
            return None

        value = getattr(event, field_name, None)
        return str(value) if value is not None else None