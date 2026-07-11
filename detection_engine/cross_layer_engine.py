"""
detection_engine/cross_layer_engine.py

Cross-layer incident correlation engine.

This engine operates AFTER normal layer-specific incidents already exist.
It reads existing open incidents from siem-incidents-* and creates
higher-level cross-layer incidents when compatible incidents from
different layers share identity and time proximity.

Pipeline position:
    raw logs → ... → incident_engine → layer incidents
                                           ↓
                            cross_layer_engine (this file)
                                           ↓
                              cross-layer incidents

Design principles:
✔ Uses EXISTING INCIDENTS only — never processes raw logs or alerts
✔ Deterministic grouping keys → no duplicate cross-layer incidents
✔ Idempotent: safe to call repeatedly on every incident cycle
✔ Defensive: never crashes the main detection engine
✔ Preserves normal layer incidents — never modifies/deletes them
✔ 16 locked cross-layer incident types — no extras, no renames

Cross-layer incident types:
 1. Web Server Compromise
 2. Confirmed Web Exploitation
 3. Host Compromise With C2
 4. Credential Compromise Chain
 5. Malware C2 Chain
 6. Reconnaissance to Exploit
 7. Data Exfiltration Chain
 8. Internal Lateral Movement
 9. Multi-Layer Intrusion Attempt
10. Exploit with Credential Theft
11. Privilege Escalation to C2
12. Distributed Credential with Recon
13. Account Compromise With Suspicious Egress
14. Account Compromise With Malware Activity
15. Confirmed Malware Staging
16. Full Kill Chain Intrusion
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from elasticsearch import Elasticsearch

try:
    from detection_engine.ai_incident_analyzer import AIIncidentAnalyzer
except ImportError:
    AIIncidentAnalyzer = None

try:
    from detection_engine.automation_notifier import AutomationNotifier
except ImportError:
    AutomationNotifier = None

log = logging.getLogger("detection_engine.cross_layer_engine")

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM_AUTH_TYPES: Set[str] = {
    "brute_force_attack",
    "targeted_account_attack",
    "password_spray_attack",
    "distributed_bruteforce_attack",
    "privilege_escalation_attempt",
    "account_compromise",
}

WEB_TYPES: Set[str] = {
    "Web Attack / Path Traversal",
    "Web Attack / SQL Injection",
    "Web Attack / XSS",
    "Web Attack / Sensitive File Probe",
    "Web Attack / Reconnaissance",
    "Web Attack / Multi-Vector Web Intrusion Attempt",
}

NETWORK_TYPES: Set[str] = {
    "Network Reconnaissance",
    "Suspicious Network Egress",
    "Possible Command and Control",
    "Suspicious DNS / Malware Staging",
}

IDS_TYPES: Set[str] = {
    "IDS / Malware Network Activity",
    "IDS / Command and Control",
    "IDS / Exploit Attempt",
    "IDS / Network Reconnaissance",
    "IDS / Credential Attack",
    "IDS / Possible Data Exfiltration",
    "IDS / Network Policy Violation",
    "IDS / Protocol Anomaly",
    "IDS / High-Severity Unknown Alert",
}

# The 16 locked cross-layer incident types
CROSS_LAYER_TYPES: Set[str] = {
    "Web Server Compromise",
    "Confirmed Web Exploitation",
    "Host Compromise With C2",
    "Credential Compromise Chain",
    "Malware C2 Chain",
    "Reconnaissance to Exploit",
    "Data Exfiltration Chain",
    "Internal Lateral Movement",
    "Multi-Layer Intrusion Attempt",
    "Exploit with Credential Theft",
    "Privilege Escalation to C2",
    "Distributed Credential with Recon",
    "Account Compromise With Suspicious Egress",
    "Account Compromise With Malware Activity",
    "Confirmed Malware Staging",
    "Full Kill Chain Intrusion",
}

ALL_LAYER_TYPES: Set[str] = (
    SYSTEM_AUTH_TYPES | WEB_TYPES | NETWORK_TYPES | IDS_TYPES
)


def _classify_layer(incident_type: str) -> Optional[str]:
    """Return the layer name for a given incident type."""
    if incident_type in SYSTEM_AUTH_TYPES:
        return "system"
    if incident_type in WEB_TYPES:
        return "web"
    if incident_type in NETWORK_TYPES:
        return "network"
    if incident_type in IDS_TYPES:
        return "ids"
    if incident_type in CROSS_LAYER_TYPES:
        return "cross_layer"
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-LAYER RULE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Each rule defines:
#   rule_id          — stable machine identifier for grouping keys
#   incident_type    — the cross-layer incident type name (locked)
#   required_groups  — list of sets; at least one incident from each set required
#   optional_groups  — list of sets; supporting evidence (not required)
#   time_window_min  — max minutes between earliest and latest incident
#   base_severity    — default severity
#   critical_when    — set of incident types whose presence upgrades to CRITICAL
#   correlation_reason — machine reason string
#   multi_layer      — True if the rule requires ≥3 layers (special matching)
#   allow_cross_input — True if existing cross-layer incidents can be input

_RULES: List[Dict[str, Any]] = [
    # ── 1. Web Server Compromise ──────────────────────────────────────────
    {
        "rule_id": "web_server_compromise",
        "incident_type": "Web Server Compromise",
        "required_groups": [
            {
                "Web Attack / SQL Injection",
                "Web Attack / Path Traversal",
                "Web Attack / Multi-Vector Web Intrusion Attempt",
            },
            {
                "Suspicious Network Egress",
                "Possible Command and Control",
            },
        ],
        "optional_groups": [],
        "time_window_min": 30,
        "base_severity": "HIGH",
        "critical_when": {"Possible Command and Control"},
        "correlation_reason": "web_attack_plus_network_egress_or_c2",
    },
    # ── 2. Confirmed Web Exploitation ─────────────────────────────────────
    {
        "rule_id": "confirmed_web_exploitation",
        "incident_type": "Confirmed Web Exploitation",
        "required_groups": [
            WEB_TYPES,  # any Web Attack
            {"IDS / Exploit Attempt"},
        ],
        "optional_groups": [],
        "time_window_min": 30,
        "base_severity": "HIGH",
        "critical_when": {"Web Attack / Multi-Vector Web Intrusion Attempt"},
        "correlation_reason": "ids_exploit_confirms_web_attack",
    },
    # ── 3. Host Compromise With C2 ────────────────────────────────────────
    {
        "rule_id": "host_compromise_with_c2",
        "incident_type": "Host Compromise With C2",
        "required_groups": [
            {
                "account_compromise",
                "brute_force_attack",
                "privilege_escalation_attempt",
            },
            {"Possible Command and Control"},
        ],
        "optional_groups": [],
        "time_window_min": 60,
        "base_severity": "CRITICAL",
        "critical_when": set(),
        "correlation_reason": "system_compromise_plus_c2",
    },
    # ── 4. Credential Compromise Chain ────────────────────────────────────
    {
        "rule_id": "credential_compromise_chain",
        "incident_type": "Credential Compromise Chain",
        "required_groups": [
            {
                "password_spray_attack",
                "targeted_account_attack",
                "distributed_bruteforce_attack",
                "brute_force_attack",
            },
            {"IDS / Credential Attack"},
        ],
        "optional_groups": [
            {"account_compromise"},
        ],
        "time_window_min": 45,
        "base_severity": "HIGH",
        "critical_when": {"account_compromise"},
        "correlation_reason": "auth_attack_plus_ids_credential",
    },
    # ── 5. Malware C2 Chain ───────────────────────────────────────────────
    {
        "rule_id": "malware_c2_chain",
        "incident_type": "Malware C2 Chain",
        "required_groups": [
            {
                "Suspicious DNS / Malware Staging",
                "Suspicious Network Egress",
            },
            {
                "IDS / Malware Network Activity",
                "IDS / Command and Control",
            },
        ],
        "optional_groups": [],
        "time_window_min": 60,
        "base_severity": "HIGH",
        "critical_when": {"IDS / Command and Control"},
        "correlation_reason": "network_staging_or_egress_plus_ids_malware_c2",
    },
    # ── 6. Reconnaissance to Exploit ──────────────────────────────────────
    {
        "rule_id": "reconnaissance_to_exploit",
        "incident_type": "Reconnaissance to Exploit",
        "required_groups": [
            {
                "Network Reconnaissance",
                "IDS / Network Reconnaissance",
            },
            {
                "IDS / Exploit Attempt",
                "Web Attack / SQL Injection",
                "Web Attack / Path Traversal",
            },
        ],
        "optional_groups": [],
        "time_window_min": 45,
        "base_severity": "HIGH",
        "critical_when": set(),
        "correlation_reason": "reconnaissance_followed_by_exploit",
    },
    # ── 7. Data Exfiltration Chain ────────────────────────────────────────
    {
        "rule_id": "data_exfiltration_chain",
        "incident_type": "Data Exfiltration Chain",
        "required_groups": [
            {"IDS / Possible Data Exfiltration"},
            {
                "Suspicious Network Egress",
                "Possible Command and Control",
            },
        ],
        "optional_groups": [],
        "time_window_min": 60,
        "base_severity": "CRITICAL",
        "critical_when": set(),
        "correlation_reason": "ids_exfiltration_plus_network_egress_or_c2",
    },
    # ── 8. Internal Lateral Movement ──────────────────────────────────────
    {
        "rule_id": "internal_lateral_movement",
        "incident_type": "Internal Lateral Movement",
        "required_groups": [
            {"account_compromise"},
            {"Network Reconnaissance"},
        ],
        "optional_groups": [],
        "time_window_min": 60,
        "base_severity": "HIGH",
        "critical_when": set(),
        "correlation_reason": "account_compromise_plus_internal_recon",
    },
    # ── 9. Multi-Layer Intrusion Attempt ──────────────────────────────────
    #    Special rule: requires incidents from ≥3 distinct layers
    #    OR any 2 of Web/System/Network plus one IDS incident.
    {
        "rule_id": "multi_layer_intrusion_attempt",
        "incident_type": "Multi-Layer Intrusion Attempt",
        "required_groups": [],  # handled by custom multi-layer logic
        "optional_groups": [],
        "time_window_min": 30,
        "base_severity": "HIGH",
        "critical_when": {
            "Possible Command and Control",
            "account_compromise",
            "IDS / Command and Control",
        },
        "correlation_reason": "multi_layer_activity",
        "multi_layer": True,
    },
    # ── 10. Exploit with Credential Theft ─────────────────────────────────
    {
        "rule_id": "exploit_with_credential_theft",
        "incident_type": "Exploit with Credential Theft",
        "required_groups": [
            {"IDS / Exploit Attempt"},
            {
                "IDS / Credential Attack",
                "brute_force_attack",
                "password_spray_attack",
                "targeted_account_attack",
                "distributed_bruteforce_attack",
            },
        ],
        "optional_groups": [],
        "time_window_min": 30,
        "base_severity": "HIGH",
        "critical_when": set(),
        "correlation_reason": "exploit_plus_credential_activity",
    },
    # ── 11. Privilege Escalation to C2 ────────────────────────────────────
    {
        "rule_id": "privilege_escalation_to_c2",
        "incident_type": "Privilege Escalation to C2",
        "required_groups": [
            {"privilege_escalation_attempt"},
            {"Possible Command and Control"},
        ],
        "optional_groups": [],
        "time_window_min": 60,
        "base_severity": "CRITICAL",
        "critical_when": set(),
        "correlation_reason": "privilege_escalation_plus_c2",
    },
    # ── 12. Distributed Credential with Recon ─────────────────────────────
    {
        "rule_id": "distributed_credential_with_recon",
        "incident_type": "Distributed Credential with Recon",
        "required_groups": [
            {"distributed_bruteforce_attack"},
            {"Network Reconnaissance"},
        ],
        "optional_groups": [],
        "time_window_min": 30,
        "base_severity": "HIGH",
        "critical_when": set(),
        "correlation_reason": "distributed_credential_attack_plus_recon",
    },
    # ── 13. Account Compromise With Suspicious Egress ─────────────────────
    {
        "rule_id": "account_compromise_with_suspicious_egress",
        "incident_type": "Account Compromise With Suspicious Egress",
        "required_groups": [
            {"account_compromise"},
            {"Suspicious Network Egress"},
        ],
        "optional_groups": [],
        "time_window_min": 30,
        "base_severity": "HIGH",
        "critical_when": set(),
        "correlation_reason": "account_compromise_plus_suspicious_egress",
    },
    # ── 14. Account Compromise With Malware Activity ──────────────────────
    {
        "rule_id": "account_compromise_with_malware_activity",
        "incident_type": "Account Compromise With Malware Activity",
        "required_groups": [
            {"account_compromise"},
            {
                "IDS / Malware Network Activity",
                "IDS / Command and Control",
            },
        ],
        "optional_groups": [],
        "time_window_min": 60,
        "base_severity": "CRITICAL",
        "critical_when": set(),
        "correlation_reason": "account_compromise_plus_ids_malware_or_c2",
    },
    # ── 15. Confirmed Malware Staging ─────────────────────────────────────
    {
        "rule_id": "confirmed_malware_staging",
        "incident_type": "Confirmed Malware Staging",
        "required_groups": [
            {"Suspicious DNS / Malware Staging"},
            {
                "IDS / Malware Network Activity",
                "IDS / Command and Control",
            },
        ],
        "optional_groups": [],
        "time_window_min": 30,
        "base_severity": "HIGH",
        "critical_when": {"IDS / Command and Control"},
        "correlation_reason": "dns_staging_confirmed_by_ids",
    },
    # ── 16. Full Kill Chain Intrusion ─────────────────────────────────────
    #    Special rule: requires ≥3 meaningful incidents from ≥3 major layers.
    #    May use certain cross-layer incidents as supporting evidence.
    {
        "rule_id": "full_kill_chain_intrusion",
        "incident_type": "Full Kill Chain Intrusion",
        "required_groups": [],  # handled by custom full-kill-chain logic
        "optional_groups": [],
        "time_window_min": 60,
        "base_severity": "CRITICAL",
        "critical_when": set(),
        "correlation_reason": "full_kill_chain_observed",
        "full_kill_chain": True,
    },
]

# Full Kill Chain — meaningful incident types
_FULL_KILL_CHAIN_MEANINGFUL: Set[str] = {
    "account_compromise",
    "privilege_escalation_attempt",
    "Web Attack / Multi-Vector Web Intrusion Attempt",
    "Web Attack / SQL Injection",
    "Web Attack / Path Traversal",
    "IDS / Malware Network Activity",
    "IDS / Command and Control",
    "Possible Command and Control",
    "IDS / Possible Data Exfiltration",
    "IDS / Exploit Attempt",
    "Suspicious Network Egress",
    "Suspicious DNS / Malware Staging",
    "Network Reconnaissance",
}

# Cross-layer types allowed as supporting input for Full Kill Chain
_FULL_KILL_CHAIN_CROSS_INPUT: Set[str] = {
    "Data Exfiltration Chain",
    "Malware C2 Chain",
    "Host Compromise With C2",
}

# ═══════════════════════════════════════════════════════════════════════════════
# BOUNDED LIST SIZES
# ═══════════════════════════════════════════════════════════════════════════════

_MAX_INCIDENT_IDS = 30
_MAX_ALERT_IDS = 50
_MAX_RULE_IDS = 50
_MAX_SOURCE_IPS = 30
_MAX_USERS = 30
_MAX_HOSTS = 30
_MAX_DEST_IPS = 30
_MAX_DEST_PORTS = 30
_MAX_CORR_REASONS = 30
_MAX_GROUPING_KEYS = 30

# ═══════════════════════════════════════════════════════════════════════════════
# SEVERITY RANKING
# ═══════════════════════════════════════════════════════════════════════════════

_SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _sev_rank(severity: Optional[str]) -> int:
    return _SEVERITY_RANK.get(str(severity or "").upper(), 0)


# ═══════════════════════════════════════════════════════════════════════════════
# INCIDENT WRAPPER — lightweight accessor for incident docs
# ═══════════════════════════════════════════════════════════════════════════════

class _IncidentView:
    """
    Read-only view over an Elasticsearch incident hit.
    Provides safe field access without modifying the source document.
    """

    __slots__ = ("hit",)

    def __init__(self, hit: Dict[str, Any]):
        self.hit = hit

    @property
    def _source(self) -> Dict[str, Any]:
        return self.hit.get("_source") or {}

    @property
    def _incident(self) -> Dict[str, Any]:
        return self._source.get("incident") or {}

    @property
    def _ctx(self) -> Dict[str, Any]:
        return self._source.get("attack_context") or {}

    @property
    def _related(self) -> Dict[str, Any]:
        return self._source.get("related") or {}

    # ── Core fields ───────────────────────────────────────────────────────

    @property
    def doc_id(self) -> str:
        return self.hit.get("_id", "")

    @property
    def doc_index(self) -> str:
        return self.hit.get("_index", "")

    @property
    def incident_id(self) -> str:
        return self._incident.get("id", "")

    @property
    def incident_type(self) -> str:
        return self._incident.get("type", "")

    @property
    def status(self) -> str:
        return self._incident.get("status", "")

    @property
    def severity(self) -> str:
        return self._incident.get("severity", "")

    @property
    def grouping_key(self) -> str:
        return self._incident.get("grouping_key", "")

    @property
    def is_cross_layer(self) -> bool:
        return bool(self._incident.get("is_cross_layer"))

    @property
    def layer(self) -> Optional[str]:
        return _classify_layer(self.incident_type)

    # ── Timestamps ────────────────────────────────────────────────────────

    @property
    def first_seen(self) -> Optional[datetime]:
        return _parse_ts(self._incident.get("first_seen"))

    @property
    def last_seen(self) -> Optional[datetime]:
        return _parse_ts(self._incident.get("last_seen"))

    # ── Identity fields (best-effort from multiple locations) ─────────────

    @property
    def source_ip(self) -> Optional[str]:
        return (
            _deep(self._source, "source.ip")
            or self._ctx.get("source_ip")
            or self._ctx.get("attacker_ip")
        )

    @property
    def host_name(self) -> Optional[str]:
        return (
            _deep(self._source, "host.name")
            or self._ctx.get("target_host")
        )

    @property
    def user_name(self) -> Optional[str]:
        return (
            _deep(self._source, "user.name")
            or self._ctx.get("primary_user")
            or self._ctx.get("compromised_user")
        )

    @property
    def destination_ip(self) -> Optional[str]:
        return _deep(self._source, "destination.ip")

    # ── Identity sets ─────────────────────────────────────────────────────

    @property
    def source_ips_seen(self) -> Set[str]:
        vals = set(_as_list(self._ctx.get("source_ips_seen")))
        if self.source_ip:
            vals.add(self.source_ip)
        return vals

    @property
    def hosts_seen(self) -> Set[str]:
        vals = set(_as_list(self._ctx.get("hosts_seen")))
        if self.host_name:
            vals.add(self.host_name)
        return vals

    @property
    def users_seen(self) -> Set[str]:
        vals = set(_as_list(self._ctx.get("users_seen")))
        if self.user_name:
            vals.add(self.user_name)
        return vals

    @property
    def destination_ips_seen(self) -> Set[str]:
        vals = set(_as_list(self._ctx.get("destination_ips_seen")))
        if self.destination_ip:
            vals.add(self.destination_ip)
        return vals

    @property
    def destination_ports_seen(self) -> List[str]:
        return _as_list(self._ctx.get("destination_ports_seen"))

    # ── Related evidence ──────────────────────────────────────────────────

    @property
    def related_alert_ids(self) -> List[str]:
        return _as_list(self._related.get("alert_ids"))

    @property
    def related_rule_ids(self) -> List[str]:
        return _as_list(self._related.get("rule_ids"))


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENGINE CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class CrossLayerEngine:
    """
    Cross-layer incident correlation engine.

    Reads existing open incidents from siem-incidents-* and creates/updates
    higher-level cross-layer incidents when compatible incidents from
    different layers share identity and time proximity.
    """

    INCIDENT_INDEX_PREFIX = "siem-incidents"

    def __init__(self, es_client: Elasticsearch):
        self.es = es_client
        self.ai_analyzer = AIIncidentAnalyzer(es_client) if AIIncidentAnalyzer else None
        self.notifier = AutomationNotifier() if AutomationNotifier else None

    def _run_ai_analysis(self, index: str, doc_id: str, incident_doc: dict) -> bool:
        """
        Safely enrich a cross-layer incident with AI analysis.

        Returns True when AI analysis was written.
        This must never break cross-layer incident creation/update.
        """
        log.info("🤖 CROSS AI HOOK CALLED index=%s doc_id=%s", index, doc_id)

        if not self.ai_analyzer:
            return False

        try:
            written = self.ai_analyzer.analyze_and_update(
                index=index,
                doc_id=doc_id,
                incident_doc=incident_doc,
                force=False,
            )

            if written:
                log.info("🤖 CROSS AI ANALYSIS WRITTEN index=%s doc_id=%s", index, doc_id)

            return bool(written)

        except Exception as exc:
            log.warning("AI cross-layer incident analysis failed safely: %s", exc)
            return False

    def _run_n8n_notification(
        self,
        index: str,
        doc_id: str,
        incident_doc: dict,
        ai_analysis: Optional[dict] = None,
    ) -> None:
        """
        Direct n8n fallback notification for cross-layer incidents.

        This is used when AI analysis does not run or does not write.
        It must never break cross-layer incident creation/update.
        """
        if not self.notifier:
            return

        try:
            self.notifier.notify(
                index,
                doc_id,
                incident_doc,
                ai_analysis or {},
            )
            log.info("📨 CROSS-LAYER n8n notification sent doc_id=%s", doc_id)

        except Exception as exc:
            log.warning("Cross-layer n8n notification failed safely: %s", exc)

    # ═══════════════════════════════════════════════════════════════════════
    # PUBLIC ENTRY POINT
    # ═══════════════════════════════════════════════════════════════════════

    def process_recent_open_incidents(self) -> None:
        """
        Main entry point called by IncidentEngine after normal incident
        creation/updates.

        Fetches recent open incidents, evaluates all 16 cross-layer rules,
        and creates/updates cross-layer incidents as needed.
        """
        try:
            incidents = self._fetch_recent_open_incidents()
            if not incidents:
                return

            # Separate layer incidents from existing cross-layer incidents
            layer_incidents: List[_IncidentView] = []
            existing_cross: List[_IncidentView] = []

            for inc in incidents:
                if inc.is_cross_layer or inc.incident_type in CROSS_LAYER_TYPES:
                    existing_cross.append(inc)
                elif inc.incident_type in ALL_LAYER_TYPES:
                    layer_incidents.append(inc)

            if not layer_incidents:
                return

            ip_groups = self._group_layer_incidents_by_source_ip(layer_incidents)

            # Evaluate each rule
            for rule in _RULES:
                try:
                    if rule.get("full_kill_chain"):
                        self._evaluate_full_kill_chain(
                            rule, layer_incidents, existing_cross
                        )
                    elif rule.get("multi_layer"):
                        self._evaluate_multi_layer(rule, layer_incidents)
                    else:
                        for source_ip, group_incidents in ip_groups.items():
                            self._evaluate_standard_rule(rule, group_incidents)
                except Exception:
                    log.exception(
                        "Cross-layer rule evaluation failed: %s",
                        rule.get("rule_id", "?"),
                    )

        except Exception:
            log.exception("Cross-layer correlation processing failed")

    def _group_layer_incidents_by_source_ip(
        self,
        incidents: List[_IncidentView],
    ) -> Dict[str, List[_IncidentView]]:
        """
        Group parent incidents by source.ip.
        If an incident has multiple source IPs, put it into each matching IP group.
        Incidents with no source IP are not grouped here.
        """
        ip_groups: Dict[str, List[_IncidentView]] = {}
        for inc in incidents:
            for ip in inc.source_ips_seen:
                ip_groups.setdefault(ip, []).append(inc)
        return ip_groups

    # ═══════════════════════════════════════════════════════════════════════
    # FETCH RECENT OPEN INCIDENTS
    # ═══════════════════════════════════════════════════════════════════════

    def _fetch_recent_open_incidents(self) -> List[_IncidentView]:
        """
        Query all open incidents from siem-incidents-*.
        Returns up to 200 most recent open incidents.
        """
        query = {
            "size": 200,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"incident.status.keyword": "open"}},
                    ]
                }
            },
            "sort": [
                {"incident.last_seen": {"order": "desc"}},
            ],
        }

        try:
            res = self.es.search(index="siem-incidents-*", body=query)
        except Exception:
            log.exception("Failed to fetch open incidents for cross-layer correlation")
            return []

        hits = res.get("hits", {}).get("hits", [])
        result: List[_IncidentView] = []

        for hit in hits:
            try:
                view = _IncidentView(hit)
                if view.incident_type:
                    result.append(view)
            except Exception:
                continue

        return result

    # ═══════════════════════════════════════════════════════════════════════
    # STANDARD RULE EVALUATION (rules 1-8, 10-15)
    # ═══════════════════════════════════════════════════════════════════════

    def _evaluate_standard_rule(
        self,
        rule: Dict[str, Any],
        incidents: List[_IncidentView],
    ) -> None:
        """
        Evaluate a standard cross-layer rule with required_groups.

        For each required group, find incidents whose type matches.
        Then try all combinations of one-per-group, check identity
        overlap and time window, and create/update cross-layer incidents.
        """
        required_groups: List[Set[str]] = rule["required_groups"]
        optional_groups: List[Set[str]] = rule.get("optional_groups", [])

        if not required_groups:
            return

        # Bucket incidents by which required group(s) they match
        group_buckets: List[List[_IncidentView]] = [
            [] for _ in required_groups
        ]

        for inc in incidents:
            for gi, group in enumerate(required_groups):
                if inc.incident_type in group:
                    group_buckets[gi].append(inc)

        # Every required group must have at least one incident
        if any(not bucket for bucket in group_buckets):
            return

        # Find compatible combinations (one from each required group)
        # Use first group as anchor, match against others
        for anchor in group_buckets[0]:
            # For each anchor, find compatible incidents from other groups
            partner_candidates: List[List[_IncidentView]] = []
            for gi in range(1, len(required_groups)):
                compatible = [
                    inc for inc in group_buckets[gi]
                    if self._share_identity(anchor, inc)
                    and self._within_window(
                        anchor, inc, rule["time_window_min"]
                    )
                ]
                partner_candidates.append(compatible)

            if any(not cands for cands in partner_candidates):
                continue

            # Take best partner from each group (most recent)
            matched: List[_IncidentView] = [anchor]
            for cands in partner_candidates:
                best = max(
                    cands,
                    key=lambda x: x.last_seen or datetime.min.replace(
                        tzinfo=timezone.utc
                    ),
                )
                matched.append(best)

            # Check optional groups for severity escalation
            optional_matched: List[_IncidentView] = []
            for opt_group in optional_groups:
                for inc in incidents:
                    if (
                        inc.incident_type in opt_group
                        and self._share_identity(anchor, inc)
                        and self._within_window(
                            anchor, inc, rule["time_window_min"]
                        )
                        and inc not in matched
                    ):
                        optional_matched.append(inc)
                        break

            all_matched = matched + optional_matched
            self._create_or_update_cross_layer(rule, all_matched)

    # ═══════════════════════════════════════════════════════════════════════
    # MULTI-LAYER INTRUSION ATTEMPT (rule 9)
    # ═══════════════════════════════════════════════════════════════════════

    def _evaluate_multi_layer(
        self,
        rule: Dict[str, Any],
        incidents: List[_IncidentView],
    ) -> None:
        """
        Multi-Layer Intrusion Attempt requires incidents from ≥3 distinct
        layers, or any 2 of Web/System/Network plus one IDS incident.
        """
        # Group incidents by layer
        by_layer: Dict[str, List[_IncidentView]] = {
            "system": [],
            "web": [],
            "network": [],
            "ids": [],
        }

        for inc in incidents:
            layer = inc.layer
            if layer and layer in by_layer:
                by_layer[layer].append(inc)

        active_layers = {
            layer for layer, incs in by_layer.items() if incs
        }

        # Need ≥3 layers, OR 2 of {web,system,network} + ids
        core_layers = active_layers & {"web", "system", "network"}
        has_ids = "ids" in active_layers

        qualifies = (
            len(active_layers) >= 3
            or (len(core_layers) >= 2 and has_ids)
        )

        if not qualifies:
            return

        # For each possible anchor incident, find identity-compatible
        # incidents across the required layers
        all_layer_incidents = [
            inc for layer_incs in by_layer.values() for inc in layer_incs
        ]

        # Group by source_ip for identity matching
        by_source_ip: Dict[str, List[_IncidentView]] = {}
        for inc in all_layer_incidents:
            ip = inc.source_ip
            if ip:
                by_source_ip.setdefault(ip, []).append(inc)

        for ip, ip_incidents in by_source_ip.items():
            if len(ip_incidents) < 3:
                continue

            # Check layer diversity
            ip_layers = {inc.layer for inc in ip_incidents if inc.layer}
            ip_core = ip_layers & {"web", "system", "network"}

            if not (
                len(ip_layers) >= 3
                or (len(ip_core) >= 2 and "ids" in ip_layers)
            ):
                continue

            # Check time window
            timestamps = [
                inc.last_seen for inc in ip_incidents if inc.last_seen
            ]
            if not timestamps:
                continue

            earliest = min(timestamps)
            latest = max(timestamps)
            if (latest - earliest) > timedelta(
                minutes=rule["time_window_min"]
            ):
                continue

            self._create_or_update_cross_layer(rule, ip_incidents)

    # ═══════════════════════════════════════════════════════════════════════
    # FULL KILL CHAIN INTRUSION (rule 16)
    # ═══════════════════════════════════════════════════════════════════════

    def _evaluate_full_kill_chain(
        self,
        rule: Dict[str, Any],
        layer_incidents: List[_IncidentView],
        existing_cross: List[_IncidentView],
    ) -> None:
        """
        Full Kill Chain Intrusion requires ≥3 meaningful incidents from
        ≥3 major layers. May also use certain cross-layer incidents as
        supporting evidence.
        """
        # Combine layer incidents with allowed cross-layer inputs
        candidate_pool: List[_IncidentView] = list(layer_incidents)
        for xinc in existing_cross:
            if xinc.incident_type in _FULL_KILL_CHAIN_CROSS_INPUT:
                candidate_pool.append(xinc)

        # Group by source_ip for identity matching
        by_source_ip: Dict[str, List[_IncidentView]] = {}
        for inc in candidate_pool:
            ip = inc.source_ip
            if ip:
                by_source_ip.setdefault(ip, []).append(inc)

        for ip, ip_incidents in by_source_ip.items():
            # Filter to meaningful types
            meaningful = [
                inc for inc in ip_incidents
                if inc.incident_type in _FULL_KILL_CHAIN_MEANINGFUL
                or inc.incident_type in _FULL_KILL_CHAIN_CROSS_INPUT
            ]

            if len(meaningful) < 3:
                continue

            # Check layer diversity (count cross-layer inputs as their
            # constituent layers for diversity purposes)
            layers_present: Set[str] = set()
            for inc in meaningful:
                layer = inc.layer
                if layer and layer != "cross_layer":
                    layers_present.add(layer)
                elif inc.incident_type in _FULL_KILL_CHAIN_CROSS_INPUT:
                    # Cross-layer inputs span multiple layers by definition
                    layers_present.update({"network", "ids"})

            if len(layers_present) < 3:
                continue

            # Check time window
            timestamps = [
                inc.last_seen for inc in meaningful if inc.last_seen
            ]
            if not timestamps:
                continue

            earliest = min(timestamps)
            latest = max(timestamps)
            if (latest - earliest) > timedelta(
                minutes=rule["time_window_min"]
            ):
                continue

            self._create_or_update_cross_layer(rule, meaningful)

    # ═══════════════════════════════════════════════════════════════════════
    # IDENTITY MATCHING
    # ═══════════════════════════════════════════════════════════════════════

    def _share_identity(
        self,
        a: _IncidentView,
        b: _IncidentView,
    ) -> bool:
        """
        Check whether two incidents share at least one meaningful identity
        field. Defensive: checks all available identity sources.

        Returns True if any overlap is found in:
          - source.ip / source_ips_seen
          - host.name / hosts_seen
          - user.name / users_seen
          - destination.ip / destination_ips_seen
        """
        # source IP overlap
        a_src_ips = a.source_ips_seen
        b_src_ips = b.source_ips_seen
        if a_src_ips and b_src_ips and (a_src_ips & b_src_ips):
            return True

        # host overlap
        a_hosts = a.hosts_seen
        b_hosts = b.hosts_seen
        if a_hosts and b_hosts and (a_hosts & b_hosts):
            return True

        # user overlap
        a_users = a.users_seen
        b_users = b.users_seen
        if a_users and b_users and (a_users & b_users):
            return True

        # destination IP overlap
        a_dest = a.destination_ips_seen
        b_dest = b.destination_ips_seen
        if a_dest and b_dest and (a_dest & b_dest):
            return True

        # Cross-check: one's source is the other's destination (common
        # in web → network correlation where web src_ip = network src_ip)
        if a_src_ips and b_dest:
            if a_src_ips & b_dest:
                return True
        if b_src_ips and a_dest:
            if b_src_ips & a_dest:
                return True

        return False

    # ═══════════════════════════════════════════════════════════════════════
    # TIME WINDOW
    # ═══════════════════════════════════════════════════════════════════════

    def _within_window(
        self,
        a: _IncidentView,
        b: _IncidentView,
        window_minutes: int,
    ) -> bool:
        """
        Check whether two incidents are within the specified time window.
        Uses the broadest overlap: compares the span from the earliest
        first_seen to the latest last_seen.
        """
        a_first = a.first_seen
        a_last = a.last_seen
        b_first = b.first_seen
        b_last = b.last_seen

        # Need at least one timestamp from each
        a_ts = a_last or a_first
        b_ts = b_last or b_first
        if not a_ts or not b_ts:
            return False

        # Use the broadest span
        earliest = min(
            t for t in [a_first, b_first] if t is not None
        )
        latest = max(
            t for t in [a_last, b_last] if t is not None
        )

        return (latest - earliest) <= timedelta(minutes=window_minutes)

    # ═══════════════════════════════════════════════════════════════════════
    # CREATE / UPDATE CROSS-LAYER INCIDENT
    # ═══════════════════════════════════════════════════════════════════════

    def _create_or_update_cross_layer(
        self,
        rule: Dict[str, Any],
        matched_incidents: List[_IncidentView],
    ) -> None:
        """
        Create or update a cross-layer incident from matched layer incidents.

        Uses deterministic grouping key to prevent duplicates.
        """
        if not matched_incidents:
            return

        rule_id: str = rule["rule_id"]
        incident_type: str = rule["incident_type"]

        all_src_ips: Set[str] = set()
        for inc in matched_incidents:
            all_src_ips |= inc.source_ips_seen

        if len(all_src_ips) > 1:
            log.warning(
                "Skipping cross-layer rule=%s due to mixed source IPs: %s",
                rule_id, list(all_src_ips)
            )
            return

        # Build grouping key from primary identity
        grouping_key = self._build_grouping_key(rule_id, matched_incidents)
        if not grouping_key:
            log.debug(
                "Cross-layer skipped (no strong identity): rule=%s", rule_id
            )
            return

        # Compute severity
        severity = self._compute_severity(rule, matched_incidents)

        # Merge all evidence from matched incidents
        evidence = self._merge_evidence(matched_incidents)

        # Build correlation reasons
        reasons = evidence.get("correlation_reasons", [])
        base_reason = rule["correlation_reason"]
        if base_reason not in reasons:
            reasons = [base_reason] + reasons

        # Check for existing cross-layer incident with this key
        existing = self._find_open_cross_layer_by_key(grouping_key)

        if existing:
            self._update_existing(
                hit=existing,
                rule=rule,
                severity=severity,
                evidence=evidence,
                reasons=reasons,
                matched_incidents=matched_incidents,
            )
        else:
            self._create_new(
                rule=rule,
                grouping_key=grouping_key,
                severity=severity,
                evidence=evidence,
                reasons=reasons,
                matched_incidents=matched_incidents,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # GROUPING KEY
    # ═══════════════════════════════════════════════════════════════════════

    def _build_grouping_key(
        self,
        rule_id: str,
        incidents: List[_IncidentView],
    ) -> Optional[str]:
        """
        Build a deterministic grouping key from the strongest available
        identity across all matched incidents.

        Format:
          cross::<rule_id>::src::<source_ip>
          cross::<rule_id>::host::<host>
          cross::<rule_id>::user::<user>::host::<host>

        Returns None if no strong identity is available.
        """
        # Collect all identity candidates
        all_src_ips: Set[str] = set()
        all_hosts: Set[str] = set()
        all_users: Set[str] = set()

        for inc in incidents:
            all_src_ips |= inc.source_ips_seen
            all_hosts |= inc.hosts_seen
            all_users |= inc.users_seen

        # Priority: source IP (most specific for network correlation)
        if all_src_ips:
            if len(all_src_ips) == 1:
                primary_ip = sorted(all_src_ips)[0]
                return f"cross::{rule_id}::src::{primary_ip}"
            else:
                return None

        # Fallback: user + host
        if all_users and all_hosts:
            primary_user = sorted(all_users)[0]
            primary_host = sorted(all_hosts)[0]
            return f"cross::{rule_id}::user::{primary_user}::host::{primary_host}"

        # Fallback: host only
        if all_hosts:
            primary_host = sorted(all_hosts)[0]
            return f"cross::{rule_id}::host::{primary_host}"

        # No strong identity — skip
        return None

    # ═══════════════════════════════════════════════════════════════════════
    # SEVERITY COMPUTATION
    # ═══════════════════════════════════════════════════════════════════════

    def _compute_severity(
        self,
        rule: Dict[str, Any],
        incidents: List[_IncidentView],
    ) -> str:
        """
        Compute severity for a cross-layer incident.
        Starts from base_severity and upgrades to CRITICAL when
        critical_when types are present.
        """
        base: str = rule["base_severity"]
        critical_when: Set[str] = rule.get("critical_when", set())

        if base == "CRITICAL":
            return "CRITICAL"

        if critical_when:
            matched_types = {inc.incident_type for inc in incidents}
            if matched_types & critical_when:
                return "CRITICAL"

        return base

    # ═══════════════════════════════════════════════════════════════════════
    # EVIDENCE MERGING
    # ═══════════════════════════════════════════════════════════════════════

    def _merge_evidence(
        self,
        incidents: List[_IncidentView],
    ) -> Dict[str, Any]:
        """
        Merge all evidence from matched incidents into a combined dict.
        All lists are bounded to prevent huge documents.
        """
        source_ips: List[str] = []
        hosts: List[str] = []
        users: List[str] = []
        dest_ips: List[str] = []
        dest_ports: List[str] = []
        layers: List[str] = []
        incident_types: List[str] = []
        incident_ids: List[str] = []
        grouping_keys: List[str] = []
        rule_ids: List[str] = []
        alert_ids: List[str] = []
        reasons: List[str] = []

        first_seen: Optional[datetime] = None
        last_seen: Optional[datetime] = None

        for inc in incidents:
            # Types and IDs
            itype = inc.incident_type
            if itype and itype not in incident_types:
                incident_types.append(itype)

            iid = inc.incident_id
            if iid and iid not in incident_ids:
                incident_ids.append(iid)

            gk = inc.grouping_key
            if gk and gk not in grouping_keys:
                grouping_keys.append(gk)

            # Layer
            layer = inc.layer
            if layer and layer not in layers:
                layers.append(layer)

            # Identity merges
            for ip in inc.source_ips_seen:
                if ip and ip not in source_ips:
                    source_ips.append(ip)
            for h in inc.hosts_seen:
                if h and h not in hosts:
                    hosts.append(h)
            for u in inc.users_seen:
                if u and u not in users:
                    users.append(u)
            for d in inc.destination_ips_seen:
                if d and d not in dest_ips:
                    dest_ips.append(d)
            for p in inc.destination_ports_seen:
                if p and p not in dest_ports:
                    dest_ports.append(p)

            # Related evidence from lower incidents
            for rid in inc.related_rule_ids:
                if rid and rid not in rule_ids:
                    rule_ids.append(rid)
            for aid in inc.related_alert_ids:
                if aid and aid not in alert_ids:
                    alert_ids.append(aid)

            # Correlation reasons from existing context
            ctx_reasons = _as_list(
                inc._ctx.get("ids_correlation_reasons")
            )
            for r in ctx_reasons:
                if r and r not in reasons:
                    reasons.append(r)

            # Timestamps
            inc_first = inc.first_seen
            inc_last = inc.last_seen
            if inc_first and (first_seen is None or inc_first < first_seen):
                first_seen = inc_first
            if inc_last and (last_seen is None or inc_last > last_seen):
                last_seen = inc_last

        return {
            "source_ips_seen": source_ips[:_MAX_SOURCE_IPS],
            "hosts_seen": hosts[:_MAX_HOSTS],
            "users_seen": users[:_MAX_USERS],
            "destination_ips_seen": dest_ips[:_MAX_DEST_IPS],
            "destination_ports_seen": dest_ports[:_MAX_DEST_PORTS],
            "layers_seen": layers,
            "related_incident_types": incident_types[:_MAX_INCIDENT_IDS],
            "related_incident_ids": incident_ids[:_MAX_INCIDENT_IDS],
            "related_grouping_keys": grouping_keys[:_MAX_GROUPING_KEYS],
            "related_rule_ids": rule_ids[:_MAX_RULE_IDS],
            "related_alert_ids": alert_ids[:_MAX_ALERT_IDS],
            "correlation_reasons": reasons[:_MAX_CORR_REASONS],
            "first_seen": _fmt_ts(first_seen),
            "last_seen": _fmt_ts(last_seen),
        }

    # ═══════════════════════════════════════════════════════════════════════
    # BUILD EVIDENCE SUMMARY
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _build_evidence_summary(
        incident_type: str,
        evidence: Dict[str, Any],
        reason: str,
    ) -> str:
        """Build a concise human-readable evidence summary."""
        parts: List[str] = [f"Cross-layer correlation: {incident_type}"]

        types = evidence.get("related_incident_types", [])
        if types:
            parts.append(f"Related incidents: {', '.join(types[:5])}")

        layers = evidence.get("layers_seen", [])
        if layers:
            parts.append(f"Layers: {', '.join(layers)}")

        src_ips = evidence.get("source_ips_seen", [])
        if src_ips:
            parts.append(f"Source IPs: {', '.join(src_ips[:5])}")

        users = evidence.get("users_seen", [])
        if users:
            parts.append(f"Users: {', '.join(users[:5])}")

        hosts = evidence.get("hosts_seen", [])
        if hosts:
            parts.append(f"Hosts: {', '.join(hosts[:5])}")

        parts.append(f"Reason: {reason}")

        return " | ".join(parts)

    # ═══════════════════════════════════════════════════════════════════════
    # CREATE NEW CROSS-LAYER INCIDENT
    # ═══════════════════════════════════════════════════════════════════════

    def _create_new(
        self,
        rule: Dict[str, Any],
        grouping_key: str,
        severity: str,
        evidence: Dict[str, Any],
        reasons: List[str],
        matched_incidents: List[_IncidentView],
    ) -> None:
        """Create a new cross-layer incident document."""
        now = self._utcnow()
        incident_id = hashlib.sha1(grouping_key.encode()).hexdigest()[:16]
        incident_type: str = rule["incident_type"]
        rule_id: str = rule["rule_id"]

        # Primary identity fields
        primary_source_ip = (
            evidence["source_ips_seen"][0]
            if evidence.get("source_ips_seen")
            else None
        )
        primary_host = (
            evidence["hosts_seen"][0]
            if evidence.get("hosts_seen")
            else None
        )
        primary_user = (
            evidence["users_seen"][0]
            if evidence.get("users_seen")
            else None
        )

        evidence_summary = self._build_evidence_summary(
            incident_type, evidence, rule["correlation_reason"]
        )

        doc: Dict[str, Any] = {
            "incident": {
                "id": incident_id,
                "version": 1,
                "type": incident_type,
                "status": "open",
                "severity": severity,
                "first_seen": evidence.get("first_seen") or _fmt_ts(now),
                "last_seen": evidence.get("last_seen") or _fmt_ts(now),
                "alert_count": 0,
                "incident_count": len(matched_incidents),
                "grouping_key": grouping_key,
                "is_cross_layer": True,
            },
            "attack_context": {
                "layer": "cross_layer",
                "layers_seen": evidence.get("layers_seen", []),
                "cross_layer_rule_id": rule_id,
                "correlation_reasons": reasons[:_MAX_CORR_REASONS],
                "source_ips_seen": evidence.get("source_ips_seen", []),
                "hosts_seen": evidence.get("hosts_seen", []),
                "users_seen": evidence.get("users_seen", []),
                "destination_ips_seen": evidence.get(
                    "destination_ips_seen", []
                ),
                "destination_ports_seen": evidence.get(
                    "destination_ports_seen", []
                ),
                "related_incident_types": evidence.get(
                    "related_incident_types", []
                ),
                "related_incident_ids": evidence.get(
                    "related_incident_ids", []
                ),
                "related_grouping_keys": evidence.get(
                    "related_grouping_keys", []
                ),
                "first_seen": evidence.get("first_seen"),
                "last_seen": evidence.get("last_seen"),
                "evidence_summary": evidence_summary,
            },
            "related": {
                "incident_ids": evidence.get("related_incident_ids", []),
                "incident_types": evidence.get(
                    "related_incident_types", []
                ),
                "grouping_keys": evidence.get(
                    "related_grouping_keys", []
                ),
                "rule_ids": evidence.get("related_rule_ids", []),
                "alert_ids": evidence.get("related_alert_ids", []),
            },
            "created_at": _fmt_ts(now),
            "updated_at": _fmt_ts(now),
        }

        # Add top-level identity fields only when available
        if primary_source_ip:
            doc["source"] = {"ip": primary_source_ip}
        if primary_host:
            doc["host"] = {"name": primary_host}
        if primary_user:
            doc["user"] = {"name": primary_user}

        index_name = self._index_name(now)

        try:
            self.es.index(
                index=index_name,
                id=incident_id,
                body=doc,
                refresh="wait_for",
            )
        except Exception:
            log.exception(
                "Failed to create cross-layer incident: type=%s key=%s",
                incident_type,
                grouping_key,
            )
            return

        log.info(
            "🧩 CROSS-LAYER INCIDENT CREATED [OPEN] type=%s severity=%s "
            "key=%s related=%s",
            incident_type,
            severity,
            grouping_key,
            evidence.get("related_incident_ids", []),
        )
        ai_written = self._run_ai_analysis(index_name, incident_id, doc)

        if not ai_written:
            self._run_n8n_notification(
                index=index_name,
                doc_id=incident_id,
                incident_doc=doc,
                ai_analysis={},
            )

    # ═══════════════════════════════════════════════════════════════════════
    # UPDATE EXISTING CROSS-LAYER INCIDENT
    # ═══════════════════════════════════════════════════════════════════════

    def _update_existing(
        self,
        hit: Dict[str, Any],
        rule: Dict[str, Any],
        severity: str,
        evidence: Dict[str, Any],
        reasons: List[str],
        matched_incidents: List[_IncidentView],
    ) -> None:
        """
        Update an existing cross-layer incident with new evidence.
        Only writes to ES if something actually changed.
        """
        now = self._utcnow()
        src = hit["_source"]
        incident = src.get("incident", {})
        ctx = src.get("attack_context", {})
        related = src.get("related", {})

        # ── Detect whether anything changed ──────────────────────────────
        old_incident_ids = set(
            related.get("incident_ids", [])
            + ctx.get("related_incident_ids", [])
        )
        new_incident_ids = set(evidence.get("related_incident_ids", []))

        old_types = set(
            related.get("incident_types", [])
            + ctx.get("related_incident_types", [])
        )
        new_types = set(evidence.get("related_incident_types", []))

        ids_changed = bool(new_incident_ids - old_incident_ids)
        types_changed = bool(new_types - old_types)
        severity_changed = _sev_rank(severity) > _sev_rank(
            incident.get("severity")
        )

        if not ids_changed and not types_changed and not severity_changed:
            return  # Nothing new — skip silently

        # ── Merge evidence into existing document ────────────────────────
        # Incident fields
        incident["version"] = incident.get("version", 1) + 1
        incident["incident_count"] = len(matched_incidents)
        incident["last_seen"] = (
            evidence.get("last_seen") or _fmt_ts(now)
        )

        # Never downgrade severity
        if _sev_rank(severity) > _sev_rank(incident.get("severity")):
            incident["severity"] = severity

        # Attack context — merge lists
        ctx["layers_seen"] = _merge_unique(
            ctx.get("layers_seen", []),
            evidence.get("layers_seen", []),
        )
        ctx["correlation_reasons"] = _merge_unique(
            ctx.get("correlation_reasons", []),
            reasons,
        )[:_MAX_CORR_REASONS]
        ctx["source_ips_seen"] = _merge_unique(
            ctx.get("source_ips_seen", []),
            evidence.get("source_ips_seen", []),
        )[:_MAX_SOURCE_IPS]
        ctx["hosts_seen"] = _merge_unique(
            ctx.get("hosts_seen", []),
            evidence.get("hosts_seen", []),
        )[:_MAX_HOSTS]
        ctx["users_seen"] = _merge_unique(
            ctx.get("users_seen", []),
            evidence.get("users_seen", []),
        )[:_MAX_USERS]
        ctx["destination_ips_seen"] = _merge_unique(
            ctx.get("destination_ips_seen", []),
            evidence.get("destination_ips_seen", []),
        )[:_MAX_DEST_IPS]
        ctx["destination_ports_seen"] = _merge_unique(
            ctx.get("destination_ports_seen", []),
            evidence.get("destination_ports_seen", []),
        )[:_MAX_DEST_PORTS]
        ctx["related_incident_types"] = _merge_unique(
            ctx.get("related_incident_types", []),
            evidence.get("related_incident_types", []),
        )[:_MAX_INCIDENT_IDS]
        ctx["related_incident_ids"] = _merge_unique(
            ctx.get("related_incident_ids", []),
            evidence.get("related_incident_ids", []),
        )[:_MAX_INCIDENT_IDS]
        ctx["related_grouping_keys"] = _merge_unique(
            ctx.get("related_grouping_keys", []),
            evidence.get("related_grouping_keys", []),
        )[:_MAX_GROUPING_KEYS]
        ctx["last_seen"] = evidence.get("last_seen") or ctx.get("last_seen")

        # Rebuild evidence summary
        incident_type = incident.get("type", rule["incident_type"])
        ctx["evidence_summary"] = self._build_evidence_summary(
            incident_type, evidence, rule["correlation_reason"]
        )

        # Related section
        related["incident_ids"] = _merge_unique(
            related.get("incident_ids", []),
            evidence.get("related_incident_ids", []),
        )[:_MAX_INCIDENT_IDS]
        related["incident_types"] = _merge_unique(
            related.get("incident_types", []),
            evidence.get("related_incident_types", []),
        )[:_MAX_INCIDENT_IDS]
        related["grouping_keys"] = _merge_unique(
            related.get("grouping_keys", []),
            evidence.get("related_grouping_keys", []),
        )[:_MAX_GROUPING_KEYS]
        related["rule_ids"] = _merge_unique(
            related.get("rule_ids", []),
            evidence.get("related_rule_ids", []),
        )[:_MAX_RULE_IDS]
        related["alert_ids"] = _merge_unique(
            related.get("alert_ids", []),
            evidence.get("related_alert_ids", []),
        )[:_MAX_ALERT_IDS]

        src["incident"] = incident
        src["attack_context"] = ctx
        src["related"] = related
        src["updated_at"] = _fmt_ts(now)

        try:
            self.es.index(
                index=hit["_index"],
                id=hit["_id"],
                body=src,
                refresh="wait_for",
            )
        except Exception:
            log.exception(
                "Failed to update cross-layer incident: type=%s key=%s",
                incident.get("type"),
                incident.get("grouping_key"),
            )
            return

        log.info(
            "🔄 CROSS-LAYER INCIDENT UPDATED type=%s severity=%s "
            "key=%s related=%s",
            incident.get("type"),
            incident.get("severity"),
            incident.get("grouping_key"),
            related.get("incident_ids", []),
        )
        ai_written = self._run_ai_analysis(hit["_index"], hit["_id"], src)

        if not ai_written:
            self._run_n8n_notification(
                index=hit["_index"],
                doc_id=hit["_id"],
                incident_doc=src,
                ai_analysis=src.get("ai_analysis") or {},
            )

    # ═══════════════════════════════════════════════════════════════════════
    # ES QUERY HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    def _find_open_cross_layer_by_key(
        self, grouping_key: str
    ) -> Optional[Dict[str, Any]]:
        """Find an existing open cross-layer incident by grouping key."""
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "incident.grouping_key.keyword": grouping_key
                            }
                        },
                        {"term": {"incident.status.keyword": "open"}},
                        {"term": {"incident.is_cross_layer": True}},
                    ]
                }
            },
        }

        try:
            res = self.es.search(index="siem-incidents-*", body=query)
            hits = res.get("hits", {}).get("hits", [])
            return hits[0] if hits else None
        except Exception:
            log.exception(
                "Failed to query cross-layer incident: key=%s", grouping_key
            )
            return None

    # ═══════════════════════════════════════════════════════════════════════
    # UTILITY HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    def _index_name(self, dt: datetime) -> str:
        return f"{self.INCIDENT_INDEX_PREFIX}-{dt.strftime('%Y.%m.%d')}"

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def _deep(doc: Any, dotted: str) -> Any:
    """Resolve a dotted key path against a nested dict."""
    if not isinstance(doc, dict):
        return None
    val = doc
    for k in dotted.split("."):
        if not isinstance(val, dict):
            return None
        val = val.get(k)
        if val is None:
            return None
    return val


def _parse_ts(val: Any) -> Optional[datetime]:
    """Parse an ISO timestamp string to a UTC-aware datetime."""
    if not val:
        return None
    try:
        return datetime.fromisoformat(
            str(val).replace("Z", "+00:00")
        )
    except Exception:
        return None


def _fmt_ts(dt: Optional[datetime]) -> Optional[str]:
    """Format a datetime to ISO string."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _as_list(val: Any) -> List[str]:
    """Safely coerce a value to a list of strings."""
    if val is None:
        return []
    if isinstance(val, str):
        return [val] if val else []
    if isinstance(val, list):
        return [str(v) for v in val if v is not None and str(v).strip()]
    return []


def _merge_unique(existing: List[str], incoming: List[str]) -> List[str]:
    """Merge two lists, preserving order and removing duplicates."""
    seen: set = set()
    result: List[str] = []
    for item in (existing or []):
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    for item in (incoming or []):
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result