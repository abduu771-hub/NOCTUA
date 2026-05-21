"""
detection_engine/rule_engine.py
Core detection logic.

Receives events, uses accumulator + state, evaluates rules, decides
when to produce alerts.

Contains:
  - AllowlistChecker: drops allowlisted events before rule evaluation
  - WatchList: in-memory watch for success-after-brute-force correlation
  - NetworkClassifier: classifies network events before rule matching
  - IDSRouter: routes network_ids_alert events to the correct IDS rule
    based on Logstash-assigned tags (Wazuh-style category chaining)
  - RuleEngine: orchestrates all detection

MUST NOT talk to Elasticsearch directly.
MUST NOT build Elasticsearch documents directly — uses alert_builder.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from . import config
from .accumulator import AccumulatorManager, AccumulatorSlot
from .alert_builder import build_alert
from .models import Event
from .rules import (
    ALL_RULES,
    RULE_SUCCESS_AFTER_BRUTE_FORCE,
    RuleDefinition,
)

log = logging.getLogger("detection_engine.rule_engine")


# ── Constants: Network Classification ────────────────────────────────────────

# Ports that indicate suspicious outbound intent.
_SUSPICIOUS_OUTBOUND_PORTS: Set[int] = {
    4444,   # Metasploit default
    1337,   # common backdoor
    31337,  # elite/backdoor
    6667,   # IRC / old C2
    9001,   # Tor / misc C2
    5555,   # Android ADB / misc
    8081,   # alternate HTTP often used by implants
}

# Noise tags produced by Logstash — network events carrying these are excluded
# from network rule evaluation.
_NETWORK_NOISE_TAGS: Set[str] = {
    "noise",
    "noise_infrastructure",
    "noise_ntp",
    "noise_mdns",
    "noise_ssdp",
    "noise_broadcast",
    "noise_multicast",
    "noise_suricata_stats",
}

# Explicit RFC1918 private IPv4 ranges allowed for internal sweep targets.
# Do not use ip.is_private here because it includes additional special-purpose
# ranges that should not count as internal enterprise sweep targets.
_RFC1918_PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    )
)

# Patterns that flag a DNS name as suspicious.
# Checked against the full domain in lower-case.
_SUSPICIOUS_DNS_KEYWORDS: Set[str] = {
    "c2",
    "malware",
    "botnet",
    "command",
    "payload",
    "cnc",
    "beacon",
    "implant",
    "rat",
    "dropper",
}

# Regex for algorithmically-generated domains (DGA heuristic):
# long consonant cluster in a single label signals random/generated name.
_DGA_CONSONANT_RE = re.compile(r"[bcdfghjklmnpqrstvwxyz]{8,}", re.IGNORECASE)

# Minimum domain length that triggers DGA suspicion.
_DGA_MIN_LENGTH = 30

# Event types that are network-flow-based.
_FLOW_EVENT_TYPES: Set[str] = {"network_flow"}

# Event types that are DNS-based.
_DNS_EVENT_TYPES: Set[str] = {"network_dns"}

# All event types that must pass through the NetworkClassifier.
# suricata_stats is included so the classifier can drop it early
# before it ever reaches the rule loop.
_NETWORK_EVENT_TYPES: Set[str] = {
    "network_flow",
    "network_dns",
    "suricata_stats",
}


def _is_private_ip(ip_value: Optional[str]) -> bool:
    """
    Return True only for RFC1918 private IPv4 addresses.

    Valid internal sweep targets:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16

    Returns False for:
      - missing values
      - invalid IPs
      - IPv6
      - public IPs
      - multicast
      - broadcast-like values
      - loopback
      - link-local
      - any non-RFC1918 special-purpose ranges
    """
    if not ip_value:
        return False

    try:
        ip_obj = ipaddress.ip_address(str(ip_value).strip())
    except ValueError:
        return False

    if ip_obj.version != 4:
        return False

    if ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local:
        return False

    if str(ip_obj) == "255.255.255.255":
        return False

    return any(ip_obj in network for network in _RFC1918_PRIVATE_IPV4_NETWORKS)


# ── Allowlist ─────────────────────────────────────────────────────────────────

class AllowlistChecker:
    """Drop events from allowlisted IPs, CIDRs, or users."""

    def __init__(
        self,
        ips: Optional[List[str]] = None,
        cidrs: Optional[List[str]] = None,
        users: Optional[List[str]] = None,
    ):
        self._ips = set(ips or config.ALLOWLISTED_IPS)

        self._networks = []
        for cidr in (cidrs or config.ALLOWLISTED_CIDRS):
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("Invalid CIDR in allowlist: %s", cidr)

        self._users = set(users or config.ALLOWLISTED_USERS)

    def is_allowed(self, event: Event) -> bool:
        """True if the event should be DROPPED."""
        if event.source_ip in self._ips:
            return True

        if event.source_ip:
            try:
                ip = ipaddress.ip_address(event.source_ip)
                for net in self._networks:
                    if ip in net:
                        return True
            except ValueError:
                pass

        if event.user in self._users:
            return True

        return False


# ── Watch List ────────────────────────────────────────────────────────────────

@dataclass
class WatchListEntry:
    """
    Recent brute-force-like attack context.

    source_ips are evidence.
    users_seen + host are the escalation correlation identity.
    """

    source_ips: List[str]
    users_seen: List[str]
    host: Optional[str]
    added_at: float
    ttl_seconds: int
    parent_rule: str
    failed_count: int


class WatchList:
    """
    Tracks recent brute-force-like attack contexts so
    success_after_brute_force can correlate by identity.

    Detection still uses source.ip.
    Escalation uses user.name + host.name.
    source.ip is kept as evidence/confidence, not as the required key.
    """

    def __init__(self, ttl_seconds: int = config.WATCH_LIST_TTL_SECONDS):
        self._entries: Dict[str, WatchListEntry] = {}
        self._ttl = ttl_seconds

    def _make_key(
        self,
        parent_rule: str,
        host: Optional[str],
        users_seen: List[str],
        source_ips: List[str],
    ) -> str:
        users_part = ",".join(sorted(set(users_seen)))
        ips_part = ",".join(sorted(set(source_ips)))
        return f"{parent_rule}|host={host}|users={users_part}|ips={ips_part}"

    def add(
        self,
        source_ip: Optional[str],
        parent_rule: str,
        users_seen: List[str],
        host: Optional[str],
        failed_count: int,
    ) -> None:
        clean_users = sorted({u for u in users_seen if u and u != "unknown"})
        clean_ips = sorted({source_ip} if source_ip else set())

        if not clean_users or not host:
            return

        key = self._make_key(
            parent_rule=parent_rule,
            host=host,
            users_seen=clean_users,
            source_ips=clean_ips,
        )

        existing = self._entries.get(key)

        if existing:
            existing.added_at = time.time()
            existing.failed_count = max(existing.failed_count, failed_count)
            existing.users_seen = sorted(set(existing.users_seen) | set(clean_users))
            existing.source_ips = sorted(set(existing.source_ips) | set(clean_ips))
            return

        self._entries[key] = WatchListEntry(
            source_ips=clean_ips,
            users_seen=clean_users,
            host=host,
            added_at=time.time(),
            ttl_seconds=self._ttl,
            parent_rule=parent_rule,
            failed_count=failed_count,
        )

    def check_success(
        self,
        source_ip: Optional[str],
        user: Optional[str],
        host: Optional[str],
    ) -> Optional[WatchListEntry]:
        """
        Success correlation.

        Required:
            same user
            same host

        Optional:
            same source.ip gives stronger confidence,
            but different source.ip is still allowed.
        """
        if not user or not host:
            return None

        self.cleanup()

        best_entry: Optional[WatchListEntry] = None
        best_score = -1

        for entry in self._entries.values():
            if entry.host != host:
                continue

            if user not in entry.users_seen:
                continue

            score = 100

            if source_ip and source_ip in entry.source_ips:
                score += 50

            if score > best_score:
                best_score = score
                best_entry = entry

        return best_entry

    def cleanup(self) -> None:
        now = time.time()

        for key, entry in list(self._entries.items()):
            if now > entry.added_at + entry.ttl_seconds:
                del self._entries[key]

    def to_dict(self) -> dict:
        self.cleanup()

        return {
            key: {
                "source_ips": entry.source_ips,
                "users_seen": entry.users_seen,
                "host": entry.host,
                "added_at": entry.added_at,
                "ttl_seconds": entry.ttl_seconds,
                "parent_rule": entry.parent_rule,
                "failed_count": entry.failed_count,
            }
            for key, entry in self._entries.items()
        }

    def from_dict(self, data: dict) -> None:
        """
        Restore watchlist state.

        Supports the new identity-based format and the old IP-keyed format:
            {
                "1.2.3.4": {
                    "targeted_user": "...",
                    "parent_rule": "...",
                    ...
                }
            }
        """
        now = time.time()

        for key, d in data.items():
            source_ips = d.get("source_ips")
            users_seen = d.get("users_seen")
            host = d.get("host")

            # Backward compatibility with old IP-based watchlist state.
            if source_ips is None:
                old_source_ip = d.get("source_ip") or key
                source_ips = [old_source_ip] if old_source_ip else []

            if users_seen is None:
                old_user = d.get("targeted_user")
                users_seen = [old_user] if old_user else []

            entry = WatchListEntry(
                source_ips=source_ips,
                users_seen=users_seen,
                host=host,
                added_at=d["added_at"],
                ttl_seconds=d["ttl_seconds"],
                parent_rule=d["parent_rule"],
                failed_count=d["failed_count"],
            )

            if now <= entry.added_at + entry.ttl_seconds:
                self._entries[key] = entry


# ── Network Classifier ────────────────────────────────────────────────────────

@dataclass
class NetworkClassification:
    """
    Result of pre-classifying a network event before rule matching.

    effective_event_types contains the original event type plus any
    additional virtual types the engine should evaluate this event against.

    Example:
        A network_flow to port 4444 might produce:
            effective_event_types = {"network_flow", "network_suspicious_outbound"}
    """
    effective_event_types: Set[str]
    should_evaluate: bool  # False means drop before rule matching


class NetworkClassifier:
    """
    Pre-classifies network events before they enter the rule loop.

    Responsibilities:
      - Reject Suricata stats and noisy infrastructure events.
      - Route network_flow events to flow-based rules.
      - Classify suspicious outbound flows in memory.
      - Classify suspicious DNS queries in memory.

    Does NOT mutate the Event object.
    Does NOT write to Elasticsearch.
    Returns a NetworkClassification that the RuleEngine uses to
    decide which rules to evaluate.
    """

    def classify(self, event: Event) -> NetworkClassification:
        """
        Classify a network event.

        Returns NetworkClassification(should_evaluate=False) if the event
        should be silently dropped before rule matching.
        """
        # Always drop Suricata stats — pure health telemetry, never attack events.
        # Logstash maps these to event.action = suricata_stats / event_type = suricata_stats.
        if event.event_type == "suricata_stats":
            return NetworkClassification(
                effective_event_types=set(),
                should_evaluate=False,
            )

        # Drop events carrying Logstash noise tags.
        event_tags: Set[str] = set(getattr(event, "tags", None) or [])
        if event_tags & _NETWORK_NOISE_TAGS:
            return NetworkClassification(
                effective_event_types=set(),
                should_evaluate=False,
            )

        effective: Set[str] = {event.event_type}

        # --- network_flow classification ---
        if event.event_type in _FLOW_EVENT_TYPES:
            dest_port = getattr(event, "destination_port", None)

            if dest_port and int(dest_port) in _SUSPICIOUS_OUTBOUND_PORTS:
                # Classify as suspicious outbound in addition to normal flow.
                effective.add("network_suspicious_outbound")
                log.debug(
                    "NetworkClassifier: flow to port %s classified as suspicious_outbound [src=%s]",
                    dest_port,
                    event.source_ip,
                )

        # --- network_dns classification ---
        elif event.event_type in _DNS_EVENT_TYPES:
            dns_name = getattr(event, "dns_question_name", None)

            if dns_name and self._is_suspicious_dns(dns_name):
                effective.add("network_suspicious_dns")
                log.debug(
                    "NetworkClassifier: DNS query '%s' classified as suspicious_dns [src=%s]",
                    dns_name,
                    event.source_ip,
                )

        return NetworkClassification(
            effective_event_types=effective,
            should_evaluate=True,
        )

    def _is_suspicious_dns(self, name: str) -> bool:
        """
        Return True if a DNS name looks suspicious.

        Checks:
          1. Contains a known suspicious keyword.
          2. Matches DGA heuristic (long random-looking label).
        """
        lower = name.lower().rstrip(".")

        # Keyword match anywhere in the domain.
        for keyword in _SUSPICIOUS_DNS_KEYWORDS:
            if keyword in lower:
                return True

        # DGA heuristic: very long domain.
        if len(lower) >= _DGA_MIN_LENGTH:
            return True

        # DGA heuristic: long consonant cluster in any label.
        for label in lower.split("."):
            if _DGA_CONSONANT_RE.search(label):
                return True

        return False


# ── IDS Router ────────────────────────────────────────────────────────────────
#
# Design rationale (Wazuh-style hierarchical chaining):
#
# Wazuh handles Suricata IDS in two passes:
#   Pass 1 — parent rule 86601: catches any event_type=alert from Suricata.
#             This is the gate. Nothing more.
#   Pass 2 — child rules (86681-86685): branch by alert.severity (1→level 15,
#             2→level 10, 3→level 5) using if_sid pointing to 86601.
#             Further child rules branch by alert.category keyword.
#
# Wazuh's key design principles replicated here:
#   1. Gate check first  — low-value/noise tags are the parent-rule filter.
#   2. Category chaining — each tag maps to exactly one rule bucket,
#      but an event may match multiple buckets (unlike elif).
#   3. Severity gate on unknown — ids_unknown only routes to a rule when
#      severity is critical or high, mirroring Wazuh's level-threshold logic.
#   4. No string parsing  — Logstash already decoded category strings into
#      structured tags; Python trusts those tags completely.
#   5. Additive routing   — multiple tags → multiple rule IDs allowed to fire,
#      exactly as Wazuh child rules each independently evaluate if_sid.
#
# _IDS_RULE_IDS is the canonical set. Any rule_id in this set is an IDS rule
# and will only be evaluated for network_ids_alert events (never for other
# event types), keeping non-IDS rules completely isolated from IDS events.

# Canonical set of all IDS rule IDs known to this engine.
# Used to guard the IDS path and prevent cross-contamination.
_IDS_RULE_IDS: Set[str] = {
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

# Tags that unconditionally suppress IDS rule evaluation.
# Equivalent to Wazuh's "noalert" or level-0 suppression rules.
_IDS_SUPPRESSION_TAGS: Set[str] = {
    "ids_info",
    "ids_low_value",
}

# Noise tags that also suppress IDS rule evaluation.
# Shared with _NETWORK_NOISE_TAGS for belt-and-suspenders protection.
_IDS_NOISE_TAGS: Set[str] = _NETWORK_NOISE_TAGS


def _is_ids_rule(rule_id: str) -> bool:
    """Return True if the given rule_id belongs to the IDS rule family."""
    return rule_id in _IDS_RULE_IDS


def _get_ids_rule_ids_for_event(event: Event) -> Set[str]:
    """
    Map Logstash-assigned IDS tags to the set of IDS rule IDs that should
    evaluate this event.

    This is the Python equivalent of Wazuh's child-rule fan-out:
    each tag independently activates its corresponding rule bucket.
    An event with both ids_malware and ids_c2 activates both rules,
    just as two independent Wazuh child rules would both fire on the
    same parent event.

    Returns an empty set if the event should be suppressed entirely.
    Does NOT mutate event.tags.
    """
    tags: Set[str] = set(getattr(event, "tags", None) or [])

    # ── Gate 1: Low-value suppression (Wazuh: level-0 noalert rule) ──────────
    # ET INFO / Not Suspicious Traffic style alerts must never become
    # SIEM alerts regardless of any other tags present.
    if tags & _IDS_SUPPRESSION_TAGS:
        return set()

    # ── Gate 2: Noise suppression ─────────────────────────────────────────────
    # Belt-and-suspenders: NetworkClassifier already drops noise events
    # for standard network_flow/dns paths, but network_ids_alert bypasses
    # that classifier. Recheck here.
    if tags & _IDS_NOISE_TAGS:
        return set()

    # ── Category routing (Wazuh-style additive child-rule fan-out) ───────────
    # Each check is independent — do NOT use elif.
    # An event tagged ids_malware + ids_c2 produces both rule IDs.
    allowed: Set[str] = set()

    if "ids_malware" in tags:
        allowed.add("network_ids_malware")

    if "ids_c2" in tags:
        allowed.add("network_ids_c2")

    if "ids_exploit" in tags:
        allowed.add("network_ids_exploit")

    if "ids_scan" in tags or "ids_recon" in tags:
        allowed.add("network_ids_scan_recon")

    if "ids_credential" in tags:
        allowed.add("network_ids_credential")

    if "ids_exfiltration" in tags:
        allowed.add("network_ids_exfiltration")

    if "ids_policy" in tags:
        allowed.add("network_ids_policy")

    if "ids_protocol_anomaly" in tags:
        allowed.add("network_ids_protocol_anomaly")

    # ── Severity gate for unknown category ────────────────────────────────────
    # Mirrors Wazuh's child-rule pattern: only escalate unknowns when
    # severity 1 (critical) or 2 (high) would fire a high-level alert.
    # Medium/low unknowns are not worth escalating — too noisy.
    if "ids_unknown" in tags:
        if "ids_severity_critical" in tags or "ids_severity_high" in tags:
            allowed.add("network_ids_unknown_high")

    return allowed


# ── Rule Engine ───────────────────────────────────────────────────────────────

# Rules whose firing should add attack context to the watch list.
_BRUTE_FORCE_RULE_IDS = frozenset({
    "ssh_bruteforce",
    "user_bruteforce_by_user",
    "password_spray",
    "distributed_bruteforce",
})

# Specific rules should be evaluated before generic rules.
_RULE_PRIORITY = {
    "password_spray": 10,
    "distributed_bruteforce": 20,
    "user_bruteforce_by_user": 30,
    "ssh_bruteforce": 40,
    "sudo_bruteforce": 50,
    "success_after_brute_force": 90,
    # Network flow/DNS rules evaluated after auth/web rules.
    "network_port_scan": 110,
    "network_internal_sweep": 120,
    "network_c2_beaconing": 130,
    "network_suspicious_outbound": 140,
    "network_suspicious_dns": 150,
    # IDS rules evaluated last — they are already pre-filtered by IDSRouter
    # and have threshold=1, so ordering within the IDS family is cosmetic.
    "network_ids_malware": 200,
    "network_ids_c2": 201,
    "network_ids_exploit": 202,
    "network_ids_scan_recon": 203,
    "network_ids_credential": 204,
    "network_ids_exfiltration": 205,
    "network_ids_policy": 206,
    "network_ids_protocol_anomaly": 207,
    "network_ids_unknown_high": 208,
}


class RuleEngine:
    """
    Orchestrates detection across all rules.

    process_event() is the single entry point.
    Returns a list of alert dicts built by alert_builder.
    """

    def __init__(self) -> None:
        self.accumulator = AccumulatorManager()
        self.watch_list = WatchList()
        self.allowlist = AllowlistChecker()
        self.network_classifier = NetworkClassifier()

        # Evaluate specific rules before generic rules, regardless of ALL_RULES order.
        self.rules = sorted(
            ALL_RULES,
            key=lambda rule: _RULE_PRIORITY.get(rule.rule_id, 100),
        )

    def _users_from_slot(self, slot: AccumulatorSlot, event: Event) -> List[str]:
        """
        Extract users involved in a fired rule.

        Permanent preferred source:
            slot.users_seen

        Safe fallback:
            event.user
        """
        users = set()

        slot_users = getattr(slot, "users_seen", None)
        if slot_users:
            try:
                users.update(u for u in slot_users if u)
            except TypeError:
                pass

        if event.user:
            users.add(event.user)

        return sorted(users)

    def _should_skip_due_to_precedence(
        self,
        rule_id: str,
        fired_rule_ids: set[str],
    ) -> bool:
        """
        Prevent weaker overlapping rules from firing after a stronger rule
        already fired in the same event pass.

        Precedence:
          - password_spray > ssh_bruteforce
          - distributed_bruteforce > user_bruteforce_by_user
          - distributed_bruteforce > ssh_bruteforce
          - user_bruteforce_by_user > ssh_bruteforce
        """
        if rule_id == "ssh_bruteforce":
            if "password_spray" in fired_rule_ids:
                return True
            if "distributed_bruteforce" in fired_rule_ids:
                return True
            if "user_bruteforce_by_user" in fired_rule_ids:
                return True

        if rule_id == "user_bruteforce_by_user":
            if "distributed_bruteforce" in fired_rule_ids:
                return True

        return False

    def _should_add_to_watchlist(
        self,
        rule_id: str,
        fired_rule_ids: set[str],
    ) -> bool:
        """
        Avoid adding weaker duplicate attack contexts to the watchlist when
        a more specific rule already fired in the same pass.
        """
        if rule_id not in _BRUTE_FORCE_RULE_IDS:
            return False

        if rule_id == "ssh_bruteforce":
            if "password_spray" in fired_rule_ids:
                return False
            if "distributed_bruteforce" in fired_rule_ids:
                return False
            if "user_bruteforce_by_user" in fired_rule_ids:
                return False

        if rule_id == "user_bruteforce_by_user":
            if "distributed_bruteforce" in fired_rule_ids:
                return False

        return True

    def _get_effective_event_types(self, event: Event) -> Optional[Set[str]]:
        """
        For network events: run the NetworkClassifier and return the effective
        set of event types to match rules against.

        For non-network events: return a single-element set with the original
        event type — no classification needed.

        Returns None if the event should be dropped entirely.

        Note: network_ids_alert is intentionally NOT in _NETWORK_EVENT_TYPES.
        IDS events bypass the NetworkClassifier entirely — they are pre-classified
        by Logstash and routed by _get_ids_rule_ids_for_event() instead.
        """
        if event.event_type in _NETWORK_EVENT_TYPES:
            classification = self.network_classifier.classify(event)

            if not classification.should_evaluate:
                log.debug(
                    "Network event dropped by classifier [type=%s src=%s dataset=%s]",
                    event.event_type,
                    event.source_ip,
                    getattr(event, "event_dataset", None),
                )
                return None

            return classification.effective_event_types

        # Non-network event — no classification needed.
        return {event.event_type}

    def _process_ids_event(self, event: Event) -> List[dict]:
        """
        Handle a network_ids_alert event end-to-end.

        This is the IDS fast-path, completely separate from the standard
        rule loop. Mirrors Wazuh's two-pass model:

          Pass 1 (gate):   _get_ids_rule_ids_for_event() — suppression +
                           tag-to-rule mapping.
          Pass 2 (fanout): evaluate each allowed IDS rule independently,
                           letting the normal accumulator path run for each.

        IDS rules are never evaluated against non-IDS events, and non-IDS
        rules are never evaluated against IDS events.
        """
        allowed_ids_rule_ids = _get_ids_rule_ids_for_event(event)

        if not allowed_ids_rule_ids:
            # Event suppressed (low-value, noise, or unroutable unknown).
            log.debug(
                "IDS event suppressed: no routing rules matched "
                "[src=%s dst=%s tags=%s]",
                event.source_ip,
                getattr(event, "destination_ip", None),
                sorted(getattr(event, "tags", None) or []),
            )
            return []

        log.info(
            "IDS event routed to rules: %s [src=%s dst=%s ids_rule_id=%s]",
            sorted(allowed_ids_rule_ids),
            event.source_ip,
            getattr(event, "destination_ip", None),
            getattr(event, "ids_rule_id", None),
        )

        alerts: List[dict] = []

        for rule in self.rules:
            # Only evaluate IDS rules in this path.
            if not _is_ids_rule(rule.rule_id):
                continue

            # Only evaluate rules that the tag router allowed.
            if rule.rule_id not in allowed_ids_rule_ids:
                continue

            # IDS rules all use trigger_event_types = ["network_ids_alert"].
            # Sanity-check in case rules.py drifts from this contract.
            if "network_ids_alert" not in rule.trigger_event_types:
                log.warning(
                    "IDS rule %s does not declare network_ids_alert in "
                    "trigger_event_types — skipping",
                    rule.rule_id,
                )
                continue

            group_key = self.accumulator._build_group_key(event, rule)
            if group_key is None:
                continue

            fired_slot = self.accumulator.process(event, rule)

            if fired_slot:
                alert = build_alert(rule, fired_slot, event)
                alerts.append(alert)

                log.warning(
                    "ALERT [%s] %s: %s",
                    rule.severity,
                    rule.rule_id,
                    alert.get("rule", {}).get("description", ""),
                )

        return alerts

    def process_event(self, event: Event) -> List[dict]:
        """
        Evaluate one event against all rules.

        Returns a list of alert dicts ready for AlertWriter.write().
        Alert documents are built by alert_builder.build_alert().
        This method never constructs Elasticsearch documents directly.

        Flow:
            1. Allowlist check — drop if matched.
            2. IDS fast-path — network_ids_alert events are routed directly
               via _process_ids_event() and bypass the standard rule loop.
               Non-IDS rules are never evaluated for these events.
            3. Effective event type resolution for all other events:
               - Network events go through NetworkClassifier first.
               - Non-network events pass through unchanged.
               - Noisy/stats network events are dropped here.
            4. Rule loop — evaluated against effective event types.
               IDS rules are skipped here (they only fire in step 2).
            5. Watchlist logic for success_after_brute_force.
            6. Standard accumulator logic for all other rules.
        """
        if self.allowlist.is_allowed(event):
            return []

        # ── Step 2: IDS fast-path ─────────────────────────────────────────────
        # network_ids_alert events have already been categorized by Logstash.
        # Route them directly to the matching IDS rules without touching the
        # standard flow classifier or the non-IDS rule loop.
        if event.event_type == "network_ids_alert":
            return self._process_ids_event(event)

        # ── Step 3: resolve effective event types for non-IDS events ─────────
        effective_event_types = self._get_effective_event_types(event)
        if effective_event_types is None:
            return []

        alerts: List[dict] = []
        fired_rule_ids: set[str] = set()

        for rule in self.rules:
            # IDS rules are never evaluated in the standard loop.
            # They are exclusively handled by _process_ids_event() above.
            if _is_ids_rule(rule.rule_id):
                continue

            # Match rule trigger against effective event types.
            # A single event may match multiple rules if it was given
            # additional virtual types by the NetworkClassifier.
            if not (effective_event_types & set(rule.trigger_event_types)):
                continue

            # ── Watchlist rule: success_after_brute_force ─────────────
            if rule.accumulator_type == "watchlist":
                watch_entry = self.watch_list.check_success(
                    source_ip=event.source_ip,
                    user=event.user,
                    host=event.host,
                )

                if watch_entry:
                    fake_slot = AccumulatorSlot(
                        rule_id=rule.rule_id,
                        group_key=f"user::{event.user}::{event.host}",
                        events=[(event.timestamp.timestamp(), event.raw_log)],
                        suppressed_until=None,
                    )

                    alert = build_alert(
                        rule,
                        fake_slot,
                        event,
                        watch_entry={
                            "parent_rule": watch_entry.parent_rule,
                            "targeted_user": event.user or "unknown",
                            "users_seen": watch_entry.users_seen,
                            "source_ips": watch_entry.source_ips,
                            "host": watch_entry.host,
                            "failed_count": watch_entry.failed_count,
                            "correlation_strategy": "identity_user_host",
                        },
                    )

                    alerts.append(alert)
                    fired_rule_ids.add(rule.rule_id)

                    log.warning(
                        "ALERT [%s] %s: %s",
                        rule.severity,
                        rule.rule_id,
                        alert.get("rule", {}).get("description", ""),
                    )

                continue

            # ── Standard accumulator rules ────────────────────────────
            if self._should_skip_due_to_precedence(rule.rule_id, fired_rule_ids):
                log.info(
                    "Rule skipped due to precedence: %s suppressed by %s",
                    rule.rule_id,
                    sorted(fired_rule_ids),
                )
                continue

            # network_internal_sweep means sweeping internal/private hosts.
            # Public HTTPS/cloud destinations must not count toward this rule,
            # but the same event may still be evaluated by C2/outbound rules.
            if rule.rule_id == "network_internal_sweep":
                destination_ip = getattr(event, "destination_ip", None)
                if not _is_private_ip(destination_ip):
                    log.debug(
                        "Skipping network_internal_sweep for non-private destination IP [src=%s dst=%s port=%s]",
                        event.source_ip,
                        destination_ip,
                        getattr(event, "destination_port", None),
                    )
                    continue

            group_key = self.accumulator._build_group_key(event, rule)
            if group_key is None:
                continue

            fired_slot = self.accumulator.process(event, rule)

            if fired_slot:
                fired_rule_ids.add(rule.rule_id)

                alert = build_alert(rule, fired_slot, event)
                alerts.append(alert)

                log.warning(
                    "ALERT [%s] %s: %s",
                    rule.severity,
                    rule.rule_id,
                    alert.get("rule", {}).get("description", ""),
                )

                # Add attack context to watch list for future success correlation.
                # Detection/classification still uses source.ip in the accumulator/rules.
                # Escalation correlation uses user.name + host.name.
                if self._should_add_to_watchlist(rule.rule_id, fired_rule_ids):
                    users_seen = self._users_from_slot(fired_slot, event)

                    self.watch_list.add(
                        source_ip=event.source_ip,
                        parent_rule=rule.rule_id,
                        users_seen=users_seen,
                        host=event.host,
                        failed_count=len(fired_slot.events),
                    )

        return alerts

    def cleanup(self) -> None:
        """Periodic maintenance — call every cycle."""
        self.accumulator.cleanup()
        self.watch_list.cleanup()