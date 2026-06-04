"""
detection_engine/incident_engine.py

Entity-based incident correlation engine.

Permanent model:
  - Detection grouping decides WHERE the attack is happening.
  - Attack context decides WHO is targeted.
  - Escalation is identity-based: user.name + host.name + time window.
  - source.ip is evidence, not a hard escalation requirement.

Fixes included:
✔ Deterministic incident IDs
✔ Race-condition safe writes with refresh=wait_for
✔ Dynamic grouping by rule family
✔ Password spray grouped by attacker IP + host
✔ Distributed brute force grouped by user + host
✔ Escalation across IP mismatch
✔ Success-after-brute-force is escalation-only
✔ Cooldown does NOT block escalation
✔ Structured users_seen enrichment from alerts
✔ Structured source_ips_seen / hosts_seen enrichment
✔ Raw-log fallback enrichment
✔ Candidate scoring / priority for duplicate overlap safety
✔ Consistent keyword usage in ES queries
✔ Auto-close inactive incidents
✔ Versioning on every update
✔ Safe field handling everywhere

Web incident upgrades (Wazuh-inspired):
✔ Wazuh-style rule category separation: RECON vs EXPLOIT
✔ Anomaly-score-inspired multi-vector severity escalation
✔ Reconnaissance alone never escalates to CRITICAL (Wazuh web_scan group logic)
✔ Same-source-IP + same-host correlation for web incidents
✔ Multi-Vector Web Intrusion Attempt type when 2+ distinct rule IDs hit
✔ Web-specific evidence: top_urls, status_codes_seen, user_agents_seen, raw_event_samples
✔ MITRE context preserved per alert and merged on updates
✔ Analyst-ready attack_context with layers field (future-ready for system/network)
✔ Web grouping key: web::ip::<source_ip>::host::<host>
✔ Per-rule inactivity timeouts consistent with WINDOWS dict
✔ Severity recalculation on every web incident update
✔ Idempotent evidence merging (no duplicates, bounded list sizes)

Network incident engine (Wazuh-inspired, v1):
✔ 4 SOC story types: Network Reconnaissance, Suspicious Network Egress,
     Possible Command and Control, Suspicious DNS / Malware Staging
✔ source.ip is the network actor identity (no host.name required)
✔ Grouping keys: network::recon/egress/c2/dns::src::<ip>
✔ Correlation: port_scan + internal_sweep → recon HIGH
✔ Correlation: suspicious_outbound + c2_beaconing  → CRITICAL C2
✔ Correlation: suspicious_outbound + suspicious_dns → HIGH C2
✔ Repeated suspicious_outbound escalates egress → C2 (alert_count threshold)
✔ Cross-story promotion: dns/egress incidents upgraded to C2 when correlated
✔ Cooldown bypass when a new network story is promoted (mirrors web is_new_web_rule)
✔ Per-rule WINDOWS entries (C2 longest, DNS medium, recon short)
✔ Bounded evidence lists: destination_ips_seen, destination_ports_seen, dns_questions_seen
✔ Existing system/web/auth incidents completely untouched
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest import result

from elasticsearch import Elasticsearch

try:
    from detection_engine.cross_layer_engine import CrossLayerEngine
except ImportError:
    CrossLayerEngine = None

try:
    from detection_engine.ai_incident_analyzer import AIIncidentAnalyzer
except ImportError:
    AIIncidentAnalyzer = None

log = logging.getLogger("detection_engine.incident_engine")


# ---------------------------------------------------------------------------
# Web rule classification — mirrors Wazuh's group tagging:
#   web,accesslog,attack,   → EXPLOIT
#   web,accesslog,recon,    → RECON
# Wazuh does NOT auto-escalate recon-only events to high severity.
# Combined recon + exploit = CRITICAL (same logic as Wazuh frequency escalation).
# ---------------------------------------------------------------------------

WEB_RECON_RULES = {
    "web_404_scanning",          # T1595.002 — Active Scanning, like Wazuh web_scan group
}

WEB_EXPLOIT_RULES = {
    "web_path_traversal",        # T1190 — Exploit Public-Facing Application
    "web_sql_injection",         # T1190
    "web_xss",                   # T1190
    "web_sensitive_file",        # T1190 — sensitive probe, borderline but still exploit-class
}

WEB_ALL_RULES = WEB_RECON_RULES | WEB_EXPLOIT_RULES

# ---------------------------------------------------------------------------
# Network rule classification — mirrors Wazuh's ids,suricata group tagging.
#
# Wazuh maps Suricata alert severity → rule level:
#   severity 1 (high)   → level 12  (CRITICAL)
#   severity 2 (medium) → level 10  (HIGH)
#   severity 3 (low)    → level 6   (MEDIUM)
#
# We mirror this intent: beaconing (repeated, confirmed behavior) = HIGH,
# correlated stories = CRITICAL, single weak signals = MEDIUM.
# ---------------------------------------------------------------------------

NETWORK_RECON_RULES = {
    "network_port_scan",         # T1595.001 — Active Scanning: Scanning IP Blocks
    "network_internal_sweep",    # T1018   — Remote System Discovery
}

NETWORK_EGRESS_RULES = {
    "network_suspicious_outbound",  # T1048 — Exfiltration Over Alternative Protocol
}

NETWORK_C2_RULES = {
    "network_c2_beaconing",      # T1071 — Application Layer Protocol (C2)
}

NETWORK_DNS_RULES = {
    "network_suspicious_dns",    # T1071.004 — DNS / T1568.002 — Dynamic Resolution
}

NETWORK_ALL_RULES = (
    NETWORK_RECON_RULES
    | NETWORK_EGRESS_RULES
    | NETWORK_C2_RULES
    | NETWORK_DNS_RULES
)

# Bounded evidence list sizes for network incidents — keeps ES docs lean
_MAX_DEST_IPS       = 20
_MAX_DEST_PORTS     = 30
_MAX_DNS_QUESTIONS  = 20
_MAX_RULE_IDS_SEEN  = 10

# Max sizes for bounded web evidence lists — keeps ES docs lean
_MAX_URLS       = 10
_MAX_USER_AGENTS = 10
_MAX_RAW_SAMPLES = 10
_MAX_STATUS_CODES = 20
_MAX_MITRE_IDS  = 20

# Wazuh-inspired: how many repeated suspicious_outbound alerts from the same
# source IP within one egress incident window before we promote to C2.
# Mirrors Wazuh's frequency="6" pattern on repeated low-severity signals.
_EGRESS_TO_C2_REPEAT_THRESHOLD = 5

# ---------------------------------------------------------------------------
# IDS (Suricata) rule classification — maps Suricata categories processed
# by Logstash → rule_engine.py → alert_builder.py into SIEM-AI rule IDs.
#
# Wazuh equivalent: each IDS rule group (ids,suricata,malware, etc.)
# produces a parent alert that feeds into incident correlation.
# ---------------------------------------------------------------------------

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

# Bounded evidence list sizes for IDS incidents — keeps ES docs lean
_MAX_IDS_RULE_IDS        = 30
_MAX_IDS_RULE_NAMES      = 30
_MAX_IDS_CATEGORIES      = 20
_MAX_IDS_TAGS            = 30
_MAX_IDS_CORR_REASONS    = 20
_MAX_IDS_SEVERITY_LABELS = 15

# IDS rule → compact story key (machine-readable, used in grouping keys)
_IDS_STORY_KEYS = {
    "network_ids_malware":          "malware",
    "network_ids_c2":               "c2",
    "network_ids_exploit":          "exploit",
    "network_ids_scan_recon":       "recon",
    "network_ids_credential":       "credential",
    "network_ids_exfiltration":     "exfiltration",
    "network_ids_policy":           "policy",
    "network_ids_protocol_anomaly": "protocol_anomaly",
    "network_ids_unknown_high":     "unknown_high",
}

# Default severity for IDS standalone incidents
_IDS_DEFAULT_SEVERITY = {
    "network_ids_malware":          "HIGH",
    "network_ids_c2":               "CRITICAL",
    "network_ids_exploit":          "HIGH",
    "network_ids_scan_recon":       "MEDIUM",
    "network_ids_credential":       "HIGH",
    "network_ids_exfiltration":     "CRITICAL",
    "network_ids_policy":           "MEDIUM",
    "network_ids_protocol_anomaly": "MEDIUM",
    "network_ids_unknown_high":     "HIGH",
}


class IncidentEngine:
    INCIDENT_INDEX_PREFIX = "siem-incidents"

    # ------------------------------------------------------------------
    # Rule → base incident type mapping.
    #
    # Network rules: multiple rules map to the same story type because
    # Wazuh groups suricata alerts into broader incident stories via
    # if_matched_group and frequency correlation — we do the same here.
    #
    # Web rules use the human-readable "Web Attack / ..." convention.
    # Multi-vector is computed dynamically; it is NOT in this dict.
    # ------------------------------------------------------------------
    RULE_TO_INCIDENT_TYPE = {
        # Auth/brute-force (unchanged)
        "ssh_bruteforce": "brute_force_attack",
        "user_bruteforce_by_user": "targeted_account_attack",
        "password_spray": "password_spray_attack",
        "distributed_bruteforce": "distributed_bruteforce_attack",
        "success_after_brute_force": "account_compromise",
        "sudo_bruteforce": "privilege_escalation_attempt",
        # Web (unchanged)
        "web_path_traversal": "Web Attack / Path Traversal",
        "web_sql_injection": "Web Attack / SQL Injection",
        "web_xss": "Web Attack / XSS",
        "web_sensitive_file": "Web Attack / Sensitive File Probe",
        "web_404_scanning": "Web Attack / Reconnaissance",
        # ----------------------------------------------------------------
        # Network — maps rule_id to the INITIAL story type.
        # Final story type may be upgraded by correlation logic.
        # ----------------------------------------------------------------
        "network_port_scan":           "Network Reconnaissance",
        "network_internal_sweep":      "Network Reconnaissance",
        "network_suspicious_outbound": "Suspicious Network Egress",
        "network_c2_beaconing":        "Possible Command and Control",
        "network_suspicious_dns":      "Suspicious DNS / Malware Staging",
        # ----------------------------------------------------------------
        # IDS (Suricata) — standalone IDS incident types.
        # Each IDS rule produces its own incident type AND may update
        # existing behavioral incidents (dual-effect design).
        # ----------------------------------------------------------------
        "network_ids_malware":          "IDS / Malware Network Activity",
        "network_ids_c2":               "IDS / Command and Control",
        "network_ids_exploit":          "IDS / Exploit Attempt",
        "network_ids_scan_recon":       "IDS / Network Reconnaissance",
        "network_ids_credential":       "IDS / Credential Attack",
        "network_ids_exfiltration":     "IDS / Possible Data Exfiltration",
        "network_ids_policy":           "IDS / Network Policy Violation",
        "network_ids_protocol_anomaly": "IDS / Protocol Anomaly",
        "network_ids_unknown_high":     "IDS / High-Severity Unknown Alert",
    }

    # Multi-vector type — assigned when 2+ distinct web rule IDs seen (Wazuh-style correlation)
    WEB_MULTI_VECTOR_TYPE = "Web Attack / Multi-Vector Web Intrusion Attempt"

    # Network story types — used for type checking, story promotion, and ES queries
    NETWORK_STORY_RECON  = "Network Reconnaissance"
    NETWORK_STORY_EGRESS = "Suspicious Network Egress"
    NETWORK_STORY_C2     = "Possible Command and Control"
    NETWORK_STORY_DNS    = "Suspicious DNS / Malware Staging"

    # IDS standalone incident story types — used for type checking and queries
    IDS_STORY_MALWARE    = "IDS / Malware Network Activity"
    IDS_STORY_C2         = "IDS / Command and Control"
    IDS_STORY_EXPLOIT    = "IDS / Exploit Attempt"
    IDS_STORY_RECON      = "IDS / Network Reconnaissance"
    IDS_STORY_CREDENTIAL = "IDS / Credential Attack"
    IDS_STORY_EXFIL      = "IDS / Possible Data Exfiltration"
    IDS_STORY_POLICY     = "IDS / Network Policy Violation"
    IDS_STORY_PROTO_ANOM = "IDS / Protocol Anomaly"
    IDS_STORY_UNKNOWN    = "IDS / High-Severity Unknown Alert"

    IDS_ALL_STORY_TYPES = {
        IDS_STORY_MALWARE, IDS_STORY_C2, IDS_STORY_EXPLOIT,
        IDS_STORY_RECON, IDS_STORY_CREDENTIAL, IDS_STORY_EXFIL,
        IDS_STORY_POLICY, IDS_STORY_PROTO_ANOM, IDS_STORY_UNKNOWN,
    }

    ESCALATABLE_TYPES = {
        "brute_force_attack",
        "targeted_account_attack",
        "password_spray_attack",
        "distributed_bruteforce_attack",
        "Web Attack / Path Traversal",
        "Web Attack / SQL Injection",
        "Web Attack / XSS",
        "Web Attack / Sensitive File Probe",
        "Web Attack / Reconnaissance",
        "Web Attack / Multi-Vector Web Intrusion Attempt",
    }

    INCIDENT_TYPE_PRIORITY = {
        # Auth
        "password_spray_attack": 100,
        "distributed_bruteforce_attack": 95,
        "targeted_account_attack": 90,
        "brute_force_attack": 80,
        # Web — multi-vector is highest among web
        "Web Attack / Multi-Vector Web Intrusion Attempt": 95,
        "Web Attack / SQL Injection": 85,
        "Web Attack / Path Traversal": 80,
        "Web Attack / XSS": 75,
        "Web Attack / Sensitive File Probe": 70,
        "Web Attack / Reconnaissance": 50,
    }

    # ------------------------------------------------------------------
    # Inactivity timeouts and cooldown windows.
    #
    # Network rules:
    #   C2 beaconing lives longest — beaconing may be slow (hours).
    #   DNS staging is medium — fast staging, moderate lifespan.
    #   Recon is shortest — scanners are noisy, don't let stale recon
    #     incidents absorb new legitimate activity.
    #   Egress is medium — exfil may be sustained or slow-drip.
    #
    # Cooldown for network rules mirrors Wazuh's no_full_log + options
    # behavior — we still write, but we don't spam ES on every raw flow.
    # network_suspicious_outbound has threshold=1 in rules.py so it
    # fires frequently; give it a larger cooldown to reduce ES pressure.
    # ------------------------------------------------------------------
    WINDOWS = {
        # Auth/system (unchanged)
        "ssh_bruteforce": {
            "incident_inactivity_timeout": 15 * 60,
            "cooldown_window": 2,
        },
        "user_bruteforce_by_user": {
            "incident_inactivity_timeout": 15 * 60,
            "cooldown_window": 2,
        },
        "password_spray": {
            "incident_inactivity_timeout": 20 * 60,
            "cooldown_window": 3,
        },
        "distributed_bruteforce": {
            "incident_inactivity_timeout": 25 * 60,
            "cooldown_window": 3,
        },
        "success_after_brute_force": {
            "incident_inactivity_timeout": 30 * 60,
            "cooldown_window": 2,
        },
        "sudo_bruteforce": {
            "incident_inactivity_timeout": 20 * 60,
            "cooldown_window": 2,
        },
        # Web (unchanged)
        "web_path_traversal": {
            "incident_inactivity_timeout": 20 * 60,
            "cooldown_window": 3,
        },
        "web_sql_injection": {
            "incident_inactivity_timeout": 20 * 60,
            "cooldown_window": 3,
        },
        "web_xss": {
            "incident_inactivity_timeout": 20 * 60,
            "cooldown_window": 3,
        },
        "web_sensitive_file": {
            "incident_inactivity_timeout": 20 * 60,
            "cooldown_window": 3,
        },
        "web_404_scanning": {
            "incident_inactivity_timeout": 15 * 60,
            "cooldown_window": 5,
        },
        # ----------------------------------------------------------------
        # Network rules
        # ----------------------------------------------------------------
        "network_port_scan": {
            # Recon: short life — scanners are noisy; don't merge stale
            # scan incidents with new lateral movement activity.
            # Wazuh equivalent: frequency window ~300s for scan groups.
            "incident_inactivity_timeout": 20 * 60,   # 20 min
            "cooldown_window": 10,                     # noisy; suppress rapid re-fires
        },
        "network_internal_sweep": {
            # Internal sweep is more targeted than port scan.
            # Give it a slightly longer window to catch slow sweeps.
            "incident_inactivity_timeout": 25 * 60,   # 25 min
            "cooldown_window": 10,
        },
        "network_suspicious_outbound": {
            # threshold=1 in rules.py — fires on every matching flow.
            # Large cooldown to avoid ES pressure from legit HTTPS.
            # Wazuh equivalent: no_full_log option on low-level flow rules.
            "incident_inactivity_timeout": 30 * 60,   # 30 min
            "cooldown_window": 30,                     # 30s cooldown per source
        },
        "network_c2_beaconing": {
            # Beaconing is already repeated behavior (rules.py threshold).
            # Long inactivity — slow beacon intervals can be hours apart.
            # Wazuh equivalent: timeframe=3600 on C2 frequency rules.
            "incident_inactivity_timeout": 60 * 60,   # 60 min
            "cooldown_window": 60,                     # 60s; beaconing fires repeatedly
        },
        "network_suspicious_dns": {
            # DNS staging: medium life. Tunneling can be sustained.
            "incident_inactivity_timeout": 30 * 60,   # 30 min
            "cooldown_window": 15,
        },
        # ----------------------------------------------------------------
        # IDS (Suricata) rules — cooldown and inactivity timeouts.
        # C2/malware: long life (confirmed threats persist).
        # Scan/policy/anomaly: medium life (noisy, moderate lifespan).
        # ----------------------------------------------------------------
        "network_ids_malware": {
            "incident_inactivity_timeout": 60 * 60,   # 60 min
            "cooldown_window": 30,
        },
        "network_ids_c2": {
            "incident_inactivity_timeout": 60 * 60,   # 60 min
            "cooldown_window": 30,
        },
        "network_ids_exploit": {
            "incident_inactivity_timeout": 30 * 60,   # 30 min
            "cooldown_window": 20,
        },
        "network_ids_scan_recon": {
            "incident_inactivity_timeout": 20 * 60,   # 20 min
            "cooldown_window": 15,
        },
        "network_ids_credential": {
            "incident_inactivity_timeout": 30 * 60,   # 30 min
            "cooldown_window": 15,
        },
        "network_ids_exfiltration": {
            "incident_inactivity_timeout": 45 * 60,   # 45 min
            "cooldown_window": 30,
        },
        "network_ids_policy": {
            "incident_inactivity_timeout": 20 * 60,   # 20 min
            "cooldown_window": 20,
        },
        "network_ids_protocol_anomaly": {
            "incident_inactivity_timeout": 20 * 60,   # 20 min
            "cooldown_window": 20,
        },
        "network_ids_unknown_high": {
            "incident_inactivity_timeout": 30 * 60,   # 30 min
            "cooldown_window": 20,
        },
    }

    USER_BASED_RULES = {
        "user_bruteforce_by_user",
        "distributed_bruteforce",
        "success_after_brute_force",
        "sudo_bruteforce",
    }

    IP_BASED_RULES = {
        "ssh_bruteforce",
        "password_spray",
    }

    # Web rules get their own dedicated grouping strategy
    WEB_RULES = WEB_ALL_RULES

    def __init__(self, es_client: Elasticsearch):
        self.es = es_client
        self.cross_layer_engine = CrossLayerEngine(es_client) if CrossLayerEngine else None
        self.ai_analyzer = AIIncidentAnalyzer(es_client) if AIIncidentAnalyzer else None
        self._last_autoclose_run: Optional[datetime] = None

    def _run_cross_layer_correlation(self) -> None:
        if not self.cross_layer_engine:
            return

        try:
            self.cross_layer_engine.process_recent_open_incidents()
        except Exception:
            log.exception("Cross-layer correlation failed")

    def _run_ai_analysis(self, index: str, doc_id: str, incident_doc: dict) -> None:
        """
        Safely enrich an incident with AI analysis.

        This must never break incident creation/update.
        """
        log.info("🤖 AI HOOK CALLED index=%s doc_id=%s", index, doc_id)

        if not self.ai_analyzer:
            return

        try:
            self.ai_analyzer.analyze_and_update(
                index=index,
                doc_id=doc_id,
                incident_doc=incident_doc,
                force=False,
            )

        except Exception as exc:
            log.warning("AI incident analysis failed safely: %s", exc)

    # =========================================================================
    # MAIN ENTRY
    # =========================================================================

    def process_alert(self, alert: dict[str, Any]) -> None:
        rule_id = self._field(alert, "rule.id")

        if rule_id not in self.RULE_TO_INCIDENT_TYPE:
            return

        # ----------------------------------------------------------------
        # Network alerts: route to dedicated network incident handler.
        # Completely separate from auth/web paths — no shared logic.
        # ----------------------------------------------------------------
        if rule_id in NETWORK_ALL_RULES:
            self._process_network_alert(alert, rule_id)
            self._auto_close_incidents()
            return

        # ----------------------------------------------------------------
        # IDS alerts: route to dedicated IDS incident handler.
        # Dual-effect: standalone IDS incident + behavioral correlation.
        # ----------------------------------------------------------------
        if rule_id in IDS_RULE_IDS:
            self._process_ids_alert(alert, rule_id)
            self._auto_close_incidents()
            return

        grouping_key = self._build_grouping_key(rule_id, alert)
        if not grouping_key:
            log.warning("Incident skipped: missing fields for %s", rule_id)
            return

        now = self._utcnow()
        ts = self._parse_ts(self._field(alert, "@timestamp")) or now
        user = self._field(alert, "user.name")

        # ----------------------------------------------------------------
        # success_after_brute_force: must only escalate an existing incident
        # ----------------------------------------------------------------
        if rule_id == "success_after_brute_force":
            existing = self._find_open_incident_by_key(grouping_key)

            if not existing:
                existing = self._find_escalation_candidate(alert, user)

            if not existing:
                log.warning(
                    "ESCALATION SKIPPED: no open attack incident matched "
                    "success user=%s host=%s source_ip=%s",
                    user,
                    self._field(alert, "host.name"),
                    self._field(alert, "source.ip"),
                )
                self._auto_close_incidents()
                return

            self._update_incident(
                hit=existing,
                alert=alert,
                incoming_rule_id=rule_id,
                grouping_key=grouping_key,
                ts=ts,
                now=now,
                user=user,
            )
            self._auto_close_incidents()
            return

        # ----------------------------------------------------------------
        # Normal path: find existing incident or create new
        # ----------------------------------------------------------------
        existing = self._find_open_incident_by_key(grouping_key)

        if existing:
            self._update_incident(
                hit=existing,
                alert=alert,
                incoming_rule_id=rule_id,
                grouping_key=grouping_key,
                ts=ts,
                now=now,
                user=user,
            )
        else:
            existing_retry = self._find_open_incident_by_key(grouping_key)

            if existing_retry:
                self._update_incident(
                    hit=existing_retry,
                    alert=alert,
                    incoming_rule_id=rule_id,
                    grouping_key=grouping_key,
                    ts=ts,
                    now=now,
                    user=user,
                )
            else:
                self._create_incident(
                    alert=alert,
                    rule_id=rule_id,
                    grouping_key=grouping_key,
                    ts=ts,
                    now=now,
                    user=user,
                )

        self._auto_close_incidents()

    # =========================================================================
    # NETWORK INCIDENT ENGINE
    # =========================================================================
    #
    # Architecture mirrors Wazuh's 4-stage pipeline:
    #   raw alert (already decoded+classified by rule_engine.py)
    #   → _process_network_alert()        [router — Wazuh: rule match]
    #   → _resolve_network_story()        [story type + key — Wazuh: group/if_sid]
    #   → _correlate_network()            [cross-story — Wazuh: if_matched_sid]
    #   → _create/_update_network_incident() [write — Wazuh: alert + active response]
    #
    # =========================================================================

    def _process_network_alert(self, alert: dict, rule_id: str) -> None:
        """
        Main router for all network alerts.

        Step 1: Extract source_ip — the network actor identity.
                No source_ip = no incident (can't group without actor).
        Step 2: Determine the initial story type and grouping key.
        Step 3: Run cross-story correlation — may redirect to a different
                (higher-priority) story key if a stronger story exists.
        Step 4: Find existing open incident or create new.
        """
        now  = self._utcnow()
        ts   = self._parse_ts(self._field(alert, "@timestamp")) or now

        source_ip = self._extract_network_source_ip(alert)
        if not source_ip:
            log.warning(
                "Network incident skipped: no source_ip extractable for rule=%s", rule_id
            )
            return

        # --- Step 2: resolve initial story ---
        story_type, grouping_key = self._resolve_network_story(rule_id, source_ip)

        # --- Step 3: cross-story correlation ---
        # This may return a DIFFERENT (promoted) key if a stronger story exists.
        # e.g. a new dns alert + existing egress incident → both fold into C2.
        promoted_key, promoted_type = self._correlate_network(
            rule_id=rule_id,
            source_ip=source_ip,
            initial_story=story_type,
            initial_key=grouping_key,
            alert=alert,
            now=now,
        )

        # Use promoted values if correlation found a better story
        final_key  = promoted_key  or grouping_key
        final_type = promoted_type or story_type

        # --- Step 4: find or create ---
        existing = self._find_open_incident_by_key(final_key)

        if existing:
            self._update_network_incident(
                hit=existing,
                alert=alert,
                rule_id=rule_id,
                final_type=final_type,
                grouping_key=final_key,
                ts=ts,
                now=now,
            )
        else:
            # Race-condition retry (mirrors auth path)
            existing_retry = self._find_open_incident_by_key(final_key)
            if existing_retry:
                self._update_network_incident(
                    hit=existing_retry,
                    alert=alert,
                    rule_id=rule_id,
                    final_type=final_type,
                    grouping_key=final_key,
                    ts=ts,
                    now=now,
                )
            else:
                self._create_network_incident(
                    alert=alert,
                    rule_id=rule_id,
                    story_type=final_type,
                    grouping_key=final_key,
                    source_ip=source_ip,
                    ts=ts,
                    now=now,
                )

    # ------------------------------------------------------------------
    # Story resolver
    # Maps rule_id → (story_type, grouping_key).
    #
    # Wazuh equivalent:
    #   <rule id="X">
    #     <group>ids,suricata,network_scan,</group>
    #   </rule>
    # The group tag is how Wazuh routes to the right incident story.
    # We do the same with explicit story keys.
    # ------------------------------------------------------------------

    def _resolve_network_story(
        self, rule_id: str, source_ip: str
    ) -> tuple[str, str]:
        """
        Returns (story_type, grouping_key) for a given rule + actor.

        Grouping key format:  network::<story>::src::<ip>
        This ensures:
          - port_scan + internal_sweep from same IP → same recon incident
          - c2_beaconing + promoted outbound → same c2 incident
          - dns staging stays separate until correlation promotes it
        """
        if rule_id in NETWORK_RECON_RULES:
            return (
                self.NETWORK_STORY_RECON,
                f"network::recon::src::{source_ip}",
            )

        if rule_id in NETWORK_EGRESS_RULES:
            return (
                self.NETWORK_STORY_EGRESS,
                f"network::egress::src::{source_ip}",
            )

        if rule_id in NETWORK_C2_RULES:
            return (
                self.NETWORK_STORY_C2,
                f"network::c2::src::{source_ip}",
            )

        if rule_id in NETWORK_DNS_RULES:
            return (
                self.NETWORK_STORY_DNS,
                f"network::dns::src::{source_ip}",
            )

        # Fallback — should never reach here given RULE_TO_INCIDENT_TYPE guard
        return (
            self.NETWORK_STORY_EGRESS,
            f"network::egress::src::{source_ip}",
        )

    # ------------------------------------------------------------------
    # Cross-story correlator
    #
    # Wazuh equivalent:
    #   <rule id="200" level="12">
    #     <if_matched_sid>101</if_matched_sid>    ← existing recon alert
    #     <if_matched_sid>102</if_matched_sid>    ← existing sweep alert
    #     <same_source_ip />
    #     <description>Possible lateral movement from recon host</description>
    #   </rule>
    #
    # We implement this by querying open incidents for the same source_ip
    # across all 4 story keys and applying promotion rules.
    #
    # Promotion rules (ordered by severity impact):
    #   C2_beaconing + suspicious_outbound → CRITICAL C2
    #   C2_beaconing + suspicious_dns      → HIGH C2 (already C2, confirm)
    #   suspicious_outbound + suspicious_dns → HIGH C2 (new promotion)
    #   port_scan + internal_sweep          → HIGH Recon (severity escalation only,
    #                                          not story change; handled in update)
    #   repeated suspicious_outbound        → C2 (egress_repeat_threshold crossed)
    # ------------------------------------------------------------------

    def _correlate_network(
        self,
        rule_id: str,
        source_ip: str,
        initial_story: str,
        initial_key: str,
        alert: dict,
        now: datetime,
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Checks whether this new alert should be folded into a stronger
        existing story rather than its own default story.

        Returns (promoted_key, promoted_type) if a promotion applies,
        or (None, None) if the initial story/key should be used as-is.

        Does NOT modify any incident here — only decides routing.
        All mutations happen in create/update methods.
        """
        # Build the C2 key for this source — the promotion target
        c2_key = f"network::c2::src::{source_ip}"

        # ----------------------------------------------------------------
        # Rule A: C2 beaconing + existing suspicious_outbound → CRITICAL C2
        # The egress incident already exists; new beaconing confirms C2.
        # Route the beaconing alert into the c2 key (may be new or existing).
        # ----------------------------------------------------------------
        if rule_id in NETWORK_C2_RULES:
            egress_key = f"network::egress::src::{source_ip}"
            egress_hit = self._find_open_incident_by_key(egress_key)
            if egress_hit:
                log.info(
                    "🔗 NETWORK CORRELATION: c2_beaconing + existing egress → "
                    "CRITICAL C2 src=%s", source_ip
                )
                # We'll route to c2 key; the update will mark it CRITICAL
                return c2_key, self.NETWORK_STORY_C2

        # ----------------------------------------------------------------
        # Rule B: suspicious_outbound + existing C2 beaconing → CRITICAL C2
        # Beaconing was already confirmed; outbound is additional evidence.
        # Route the outbound alert into the existing c2 incident.
        # ----------------------------------------------------------------
        if rule_id in NETWORK_EGRESS_RULES:
            c2_hit = self._find_open_incident_by_key(c2_key)
            if c2_hit:
                log.info(
                    "🔗 NETWORK CORRELATION: suspicious_outbound + existing c2 → "
                    "CRITICAL C2 src=%s", source_ip
                )
                return c2_key, self.NETWORK_STORY_C2

        # ----------------------------------------------------------------
        # Rule C: suspicious_outbound + existing suspicious_dns → HIGH C2
        # Neither alone is C2, but together they form a C2 story.
        # Create a new C2 incident (or update if one already exists).
        # ----------------------------------------------------------------
        if rule_id in NETWORK_EGRESS_RULES:
            dns_key  = f"network::dns::src::{source_ip}"
            dns_hit  = self._find_open_incident_by_key(dns_key)
            if dns_hit:
                log.info(
                    "🔗 NETWORK CORRELATION: suspicious_outbound + existing dns → "
                    "HIGH C2 src=%s", source_ip
                )
                return c2_key, self.NETWORK_STORY_C2

        # ----------------------------------------------------------------
        # Rule D: suspicious_dns + existing suspicious_outbound → HIGH C2
        # Mirror of Rule C from the DNS side.
        # ----------------------------------------------------------------
        if rule_id in NETWORK_DNS_RULES:
            egress_key = f"network::egress::src::{source_ip}"
            egress_hit = self._find_open_incident_by_key(egress_key)
            if egress_hit:
                log.info(
                    "🔗 NETWORK CORRELATION: suspicious_dns + existing egress → "
                    "HIGH C2 src=%s", source_ip
                )
                return c2_key, self.NETWORK_STORY_C2

        # ----------------------------------------------------------------
        # Rule E: repeated suspicious_outbound → promote egress to C2
        # Wazuh equivalent: frequency="N" same_source_ip on outbound rules.
        # We check the existing egress incident's alert_count.
        # ----------------------------------------------------------------
        if rule_id in NETWORK_EGRESS_RULES:
            egress_key = f"network::egress::src::{source_ip}"
            egress_hit = self._find_open_incident_by_key(egress_key)
            if egress_hit:
                existing_count = (
                    egress_hit["_source"]
                    .get("incident", {})
                    .get("alert_count", 0)
                )
                if existing_count >= _EGRESS_TO_C2_REPEAT_THRESHOLD:
                    log.info(
                        "🔗 NETWORK CORRELATION: repeated suspicious_outbound "
                        "(count=%d >= %d) → C2 src=%s",
                        existing_count,
                        _EGRESS_TO_C2_REPEAT_THRESHOLD,
                        source_ip,
                    )
                    return c2_key, self.NETWORK_STORY_C2

        # No promotion applies — use initial story
        return None, None

    # ------------------------------------------------------------------
    # Network incident CREATE
    # ------------------------------------------------------------------

    def _create_network_incident(
        self,
        alert: dict,
        rule_id: str,
        story_type: str,
        grouping_key: str,
        source_ip: str,
        ts: datetime,
        now: datetime,
    ) -> None:
        """
        Creates a new network incident document.

        Document shape follows existing incident_engine conventions so
        dashboards, auto-close, and alert_writer need zero changes.

        attack_context.network_story is the machine-readable story key
        used by future correlation passes and dashboard queries.
        """
        incident_id = hashlib.sha1(grouping_key.encode()).hexdigest()[:16]

        severity     = self._compute_network_severity(rule_id, story_type, alert=alert)
        destination  = self._extract_network_destination(alert)
        dns_name     = self._extract_network_dns_name(alert)

        # Build the initial network attack context (evidence bag)
        attack_ctx = self._build_initial_network_attack_context(
            alert=alert,
            rule_id=rule_id,
            story_type=story_type,
            source_ip=source_ip,
            destination=destination,
            dns_name=dns_name,
            ts=ts,
        )

        doc = {
            "incident": {
                "id": incident_id,
                "version": 1,
                "type": story_type,
                "status": "open",
                "severity": severity,
                "first_seen": self._fmt_ts(ts),
                "last_seen": self._fmt_ts(ts),
                "alert_count": 1,
                "grouping_key": grouping_key,
            },
            "source": {
                "ip": source_ip,
            },
            # destination at top level — mirrors Wazuh alert schema
            "destination": {
                k: v for k, v in destination.items() if v is not None
            },
            "attack_context": attack_ctx,
            "related": {
                "alert_ids": self._alert_ids_from_alert(alert),
                "rule_ids": [rule_id],
            },
            "created_at": self._fmt_ts(now),
            "updated_at": self._fmt_ts(now),
        }

        self.es.index(
            index=self._index_name(now),
            id=incident_id,
            body=doc,
            refresh="wait_for",
        )

        log.info(
            "🆕 NETWORK INCIDENT CREATED [OPEN] type=%s severity=%s "
            "src=%s key=%s rule=%s",
            story_type,
            severity,
            source_ip,
            grouping_key,
            rule_id,
        )
        self._run_ai_analysis(self._index_name(now), incident_id, doc)
        self._run_cross_layer_correlation()

    # ------------------------------------------------------------------
    # Network incident UPDATE
    # ------------------------------------------------------------------

    def _update_network_incident(
        self,
        hit: dict,
        alert: dict,
        rule_id: str,
        final_type: str,
        grouping_key: str,
        ts: datetime,
        now: datetime,
    ) -> None:
        """
        Updates an existing network incident.

        Key behaviors:
        - Cooldown enforced per existing pattern; bypass if story is
          being promoted (is_story_promotion mirrors is_new_web_rule).
        - Severity recalculated after every rule_id merge.
        - Evidence lists (dest_ips, dest_ports, dns_questions) are
          idempotently merged and bounded.
        - Story type upgraded if correlation demanded it (final_type).
        """
        src      = hit["_source"]
        incident = src["incident"]

        existing_type    = incident.get("type", "")
        existing_key     = incident.get("grouping_key", grouping_key)

        # Ensure context bag is initialised (upgrade path for old docs)
        if "attack_context" not in src or not isinstance(src["attack_context"], dict):
            src["attack_context"] = {}
        ctx = src["attack_context"]
        self._ensure_network_attack_context(ctx)

        # ----------------------------------------------------------------
        # Cooldown logic — mirrors web is_new_web_rule bypass.
        # A story promotion always bypasses cooldown because the incident
        # is genuinely changing its nature (e.g. egress → C2).
        # A new rule_id from the same family also bypasses (first time
        # internal_sweep arrives into an existing port_scan recon incident).
        # ----------------------------------------------------------------
        last_seen  = self._parse_ts(incident.get("last_seen")) or now
        cooldown   = self.WINDOWS.get(rule_id, {}).get("cooldown_window", 10)
        elapsed    = (now - last_seen).total_seconds()

        existing_rule_ids = set(ctx.get("network_rule_ids_seen") or [])
        is_new_rule_id    = rule_id not in existing_rule_ids

        # Story promotion: final_type is stronger than what incident currently holds
        is_story_promotion = (
            final_type != existing_type
            and self._network_story_priority(final_type)
            > self._network_story_priority(existing_type)
        )

        bypass_cooldown = is_story_promotion or is_new_rule_id

        if not bypass_cooldown and elapsed < cooldown:
            log.warning(
                "⏸️ NETWORK INCIDENT SKIPPED DUE TO COOLDOWN "
                "rule=%s key=%s type=%s elapsed=%.1fs cooldown=%ss alerts=%s",
                rule_id,
                existing_key,
                existing_type,
                elapsed,
                int(cooldown),
                incident.get("alert_count", 0),
            )
            return

        # ----------------------------------------------------------------
        # Enrich evidence
        # ----------------------------------------------------------------
        self._enrich_network_context_from_alert(alert, rule_id, ctx, ts)

        # ----------------------------------------------------------------
        # Story promotion: upgrade type and recompute severity
        # Wazuh: if_matched_sid escalation — parent rule changes the group.
        # ----------------------------------------------------------------
        if is_story_promotion:
            old_type = incident["type"]
            incident["type"] = final_type
            log.info(
                "🔥 NETWORK INCIDENT PROMOTED %s → %s src=%s key=%s",
                old_type,
                final_type,
                src.get("source", {}).get("ip", "?"),
                existing_key,
            )

        # Recompute severity after any enrichment — rule_ids_seen may have grown
        incident["severity"] = self._compute_network_severity(
            rule_id=rule_id,
            story_type=incident["type"],
            ctx=ctx,
        )

        # ----------------------------------------------------------------
        # Standard update fields — identical pattern to web/auth updates
        # ----------------------------------------------------------------
        incident["version"]     = incident.get("version", 1) + 1
        incident["alert_count"] = incident.get("alert_count", 0) + 1
        incident["last_seen"]   = self._fmt_ts(ts)

        src.setdefault("related", {})
        src["related"].setdefault("alert_ids", [])
        src["related"].setdefault("rule_ids", [])

        new_alert_ids = self._alert_ids_from_alert(alert)
        src["related"]["alert_ids"] = list(
            set(src["related"]["alert_ids"] + new_alert_ids)
        )
        if rule_id not in src["related"]["rule_ids"]:
            src["related"]["rule_ids"].append(rule_id)

        src["updated_at"] = self._fmt_ts(now)

        self._save(hit, src)

        log.info(
            "🔄 NETWORK INCIDENT UPDATED key=%s type=%s severity=%s "
            "alerts=%s rule=%s",
            existing_key,
            incident["type"],
            incident.get("severity", "?"),
            incident["alert_count"],
            rule_id,
        )
        self._run_ai_analysis(hit["_index"], hit["_id"], src)
        self._run_cross_layer_correlation()

    # ------------------------------------------------------------------
    # Network attack_context helpers
    # ------------------------------------------------------------------

    def _build_initial_network_attack_context(
        self,
        alert: dict,
        rule_id: str,
        story_type: str,
        source_ip: str,
        destination: dict,
        dns_name: Optional[str],
        ts: datetime,
    ) -> dict:
        """
        Constructs the first version of attack_context for a network incident.

        Wazuh equivalent fields we mirror:
          attack_context.layer        ↔ Wazuh rule group "network"
          network_story               ↔ Wazuh rule description / category
          network_rule_ids_seen       ↔ Wazuh if_matched_sid accumulation
          destination_ips_seen        ↔ Wazuh different_dst_ip cardinality
          destination_ports_seen      ↔ Wazuh different_dst_port cardinality
          dns_questions_seen          ↔ Wazuh dns.query field list
        """
        ts_str = self._fmt_ts(ts)

        ctx: dict[str, Any] = {
            # Story-level metadata
            "layer": "network",
            "network_story": self._story_to_machine_key(story_type),
            # Wazuh-style rule tracking — drives severity recalculation
            "network_rule_ids_seen": [],
            "network_attack_types_seen": [],
            # Actor identity
            "source_ip": source_ip,
            # Evidence bags — bounded, idempotent
            "destination_ips_seen": [],
            "destination_ports_seen": [],
            "dns_questions_seen": [],
            # Timestamps
            "first_seen": ts_str,
            "last_seen": ts_str,
            "alert_count": 0,
            # Compatibility with existing incident_engine context fields
            # (kept so any shared dashboard query on users_seen / hosts_seen
            #  doesn't break; network incidents simply leave these empty)
            "users_seen": [],
            "source_ips_seen": [source_ip],
            "hosts_seen": [],
            "primary_user": None,
            "compromised_user": None,
            "grouping_strategy": "network_source_ip",
        }

        # Run enrichment immediately so first doc has full evidence
        self._enrich_network_context_from_alert(alert, rule_id, ctx, ts)
        return ctx

    def _ensure_network_attack_context(self, ctx: dict) -> None:
        """
        Guarantees all network evidence keys exist on the context dict.
        Handles upgrade path for incidents created before network support.
        """
        ctx.setdefault("layer", "network")
        ctx.setdefault("network_story", "unknown")
        ctx.setdefault("network_rule_ids_seen", [])
        ctx.setdefault("network_attack_types_seen", [])
        ctx.setdefault("source_ip", None)
        ctx.setdefault("destination_ips_seen", [])
        ctx.setdefault("destination_ports_seen", [])
        ctx.setdefault("dns_questions_seen", [])
        ctx.setdefault("first_seen", None)
        ctx.setdefault("last_seen", None)
        ctx.setdefault("alert_count", 0)
        ctx.setdefault("users_seen", [])
        ctx.setdefault("source_ips_seen", [])
        ctx.setdefault("hosts_seen", [])
        ctx.setdefault("primary_user", None)
        ctx.setdefault("compromised_user", None)
        ctx.setdefault("grouping_strategy", "network_source_ip")

    def _enrich_network_context_from_alert(
        self,
        alert: dict,
        rule_id: str,
        ctx: dict,
        ts: datetime,
    ) -> None:
        """
        Merges network evidence from one alert into the incident context.

        Wazuh philosophy:
        - destination cardinality (different_dst_ip) tracked via dest_ips_seen
        - port cardinality (different_dst_port) tracked via dest_ports_seen
        - dns_questions_seen = DNS staging evidence list
        - rule_ids_seen drives severity recalculation (anomaly scoring)
        - all lists are bounded — Wazuh uses no_full_log on noisy flow rules
        """
        ts_str = self._fmt_ts(ts)

        # --- rule tracking ---
        rule_ids = ctx.get("network_rule_ids_seen", [])
        if rule_id and rule_id not in rule_ids:
            ctx["network_rule_ids_seen"] = (rule_ids + [rule_id])[:_MAX_RULE_IDS_SEEN]

        initial_type = self.RULE_TO_INCIDENT_TYPE.get(rule_id)
        attack_types = ctx.get("network_attack_types_seen", [])
        if initial_type and initial_type not in attack_types:
            ctx["network_attack_types_seen"] = attack_types + [initial_type]

        # --- timestamps ---
        if ts_str:
            if not ctx.get("first_seen"):
                ctx["first_seen"] = ts_str
            ctx["last_seen"] = ts_str

        # --- alert count ---
        ctx["alert_count"] = ctx.get("alert_count", 0) + 1

        # --- destination IP ---
        dest_ip = self._extract_field_priority(
            alert,
            "destination.ip",
            "attack_context.destination_ip",
        )
        if dest_ip:
            dest_ips = ctx.get("destination_ips_seen", [])
            if dest_ip not in dest_ips:
                ctx["destination_ips_seen"] = (dest_ips + [dest_ip])[:_MAX_DEST_IPS]

        # --- destination port ---
        dest_port = self._extract_field_priority(
            alert,
            "destination.port",
            "attack_context.destination_port",
        )
        if dest_port is not None:
            port_str = str(dest_port)
            ports = ctx.get("destination_ports_seen", [])
            if port_str not in ports:
                ctx["destination_ports_seen"] = (ports + [port_str])[:_MAX_DEST_PORTS]

        # --- DNS question name ---
        dns_name = self._extract_network_dns_name(alert)
        if dns_name:
            dns_qs = ctx.get("dns_questions_seen", [])
            if dns_name not in dns_qs:
                ctx["dns_questions_seen"] = (dns_qs + [dns_name])[:_MAX_DNS_QUESTIONS]

        # --- source_ips_seen (compatibility) ---
        source_ip = self._extract_network_source_ip(alert)
        if source_ip:
            src_ips = set(ctx.get("source_ips_seen") or [])
            src_ips.add(source_ip)
            ctx["source_ips_seen"] = sorted(src_ips)
            if not ctx.get("source_ip"):
                ctx["source_ip"] = source_ip

        # --- network metadata from alert (informational) ---
        for field_key, ctx_key in (
            ("network.transport", "network_transport"),
            ("network.protocol",  "network_protocol"),
            ("network.bytes",     "network_bytes_last"),
            ("network.packets",   "network_packets_last"),
            ("event.dataset",     "event_dataset"),
            ("event.action",      "event_action"),
        ):
            val = self._field(alert, field_key)
            if val is not None and ctx_key not in ctx:
                ctx[ctx_key] = val

    # ------------------------------------------------------------------
    # Network severity model
    #
    # Wazuh reference levels:
    #   86601  level=3   → any Suricata alert (baseline)
    #   Custom level=6   → single behavioral signal (MEDIUM)
    #   Custom level=9   → confirmed behavioral pattern (HIGH)
    #   Custom level=12  → correlated multi-signal C2 (CRITICAL)
    #
    # Our model:
    #   MEDIUM  → single recon rule or single DNS rule (weak signal)
    #   HIGH    → dual recon rules, beaconing alone, DNS+outbound,
    #             or outbound+beaconing (confirmed behavior or correlated)
    #   CRITICAL → beaconing+outbound+any, or C2 story with 3+ rule types
    # ------------------------------------------------------------------

    def _compute_network_severity(
        self,
        rule_id: str,
        story_type: str,
        alert: dict = None,
        ctx: dict = None,
    ) -> str:
        """
        Computes network incident severity.

        Called on create (no ctx yet → use rule_id + story_type alone)
        and on every update (ctx available → use accumulated rule_ids_seen).

        Wazuh anomaly-scoring equivalent:
          1 signal  → MEDIUM
          2 signals → HIGH
          3+ signals / C2 story → CRITICAL
        """
        rule_ids_seen: set[str] = set()

        if ctx:
            rule_ids_seen = set(ctx.get("network_rule_ids_seen") or [])

        # Always include the current rule
        rule_ids_seen.add(rule_id)

        # C2 story is the most severe by definition
        if story_type == self.NETWORK_STORY_C2:
            # CRITICAL if we have 2+ distinct signals confirming C2
            c2_signals = rule_ids_seen & (
                NETWORK_C2_RULES | NETWORK_EGRESS_RULES | NETWORK_DNS_RULES
            )
            if len(c2_signals) >= 2:
                return "CRITICAL"
            return "HIGH"

        # Recon story
        if story_type == self.NETWORK_STORY_RECON:
            # Both scan types seen → HIGH (Wazuh: frequency escalation on recon)
            if rule_ids_seen & NETWORK_RECON_RULES == NETWORK_RECON_RULES:
                return "HIGH"
            return "MEDIUM"

        # Egress story
        if story_type == self.NETWORK_STORY_EGRESS:
            # Egress alone is HIGH — it's already threshold-based in rules.py
            return "HIGH"

        # DNS staging
        if story_type == self.NETWORK_STORY_DNS:
            # DNS alone: MEDIUM. Should rarely stay alone long
            # (correlation will promote to C2 if outbound also present).
            return "MEDIUM"

        # Fallback
        return "MEDIUM"

    # ------------------------------------------------------------------
    # Network story priority — used to decide if a promotion applies
    # ------------------------------------------------------------------

    def _network_story_priority(self, story_type: str) -> int:
        """
        Numeric priority for network story types.
        Higher = more severe. Used to gate story promotions:
        only promote upward, never downgrade.

        Mirrors Wazuh's rule level hierarchy.
        """
        return {
            self.NETWORK_STORY_RECON:  1,
            self.NETWORK_STORY_DNS:    2,
            self.NETWORK_STORY_EGRESS: 3,
            self.NETWORK_STORY_C2:     4,
        }.get(story_type, 0)

    def _story_to_machine_key(self, story_type: str) -> str:
        """Human-readable story type → compact machine key for ES queries."""
        return {
            self.NETWORK_STORY_RECON:  "recon",
            self.NETWORK_STORY_EGRESS: "egress",
            self.NETWORK_STORY_C2:     "c2",
            self.NETWORK_STORY_DNS:    "dns",
        }.get(story_type, "unknown")

    # ------------------------------------------------------------------
    # Network field extraction helpers
    # ------------------------------------------------------------------

    def _extract_network_source_ip(self, alert: dict) -> Optional[str]:
        """
        Priority order per spec:
          1. alert["source"]["ip"]
          2. alert["attack_context"]["source_ip"]
        """
        return self._extract_field_priority(
            alert,
            "source.ip",
            "attack_context.source_ip",
        )

    def _extract_network_destination(self, alert: dict) -> dict:
        """
        Returns a dict with ip and port (both optional).
        Defensive: never raises, never inserts None-equivalent strings.
        """
        ip = self._extract_field_priority(
            alert,
            "destination.ip",
            "attack_context.destination_ip",
        )
        port = self._extract_field_priority(
            alert,
            "destination.port",
            "attack_context.destination_port",
        )
        result: dict[str, Any] = {}
        if ip is not None:
            result["ip"] = ip
        if port is not None:
            result["port"] = port
        return result

    def _extract_network_dns_name(self, alert: dict) -> Optional[str]:
        """
        Priority order per spec:
          1. alert["dns"]["question"]["name"]
          2. alert["attack_context"]["dns_question_name"]
        """
        # Nested path dns.question.name — need to walk manually
        dns_block = self._field(alert, "dns")
        if isinstance(dns_block, dict):
            question = dns_block.get("question")
            if isinstance(question, dict):
                name = question.get("name")
                if name:
                    return str(name)

        return self._extract_field_priority(
            alert,
            "attack_context.dns_question_name",
        )

    def _extract_field_priority(self, alert: dict, *dotted_paths: str) -> Any:
        """
        Returns the first non-None value found across the given dotted paths.
        Used for network fields that may live in multiple alert shapes.
        """
        for path in dotted_paths:
            val = self._field(alert, path)
            if val is not None:
                return val
        return None


    # =========================================================================
    # IDS INCIDENT ENGINE
    # =========================================================================
    #
    # Dual-effect design:
    #   Effect A — create/update standalone IDS incidents.
    #   Effect B — correlate IDS evidence into compatible behavioral incidents.
    #
    # IDS alerts are already categorized by Logstash and routed by rule_engine.py.
    # This section never parses raw logs or Suricata signatures.
    # =========================================================================

    def _process_ids_alert(self, alert: dict, rule_id: str) -> None:
        """
        Main router for all Suricata IDS alerts.

        Creates/updates a standalone IDS incident and then correlates the same
        IDS evidence into compatible behavioral incidents when an open match
        exists for the same source identity.
        """
        now = self._utcnow()
        ts = self._parse_ts(self._field(alert, "@timestamp")) or now

        source_ip = self._extract_network_source_ip(alert)
        if not source_ip:
            log.warning("IDS incident skipped: no source_ip extractable for rule=%s", rule_id)
            return

        story_type, story_key = self._resolve_ids_story(rule_id)
        grouping_key = self._build_ids_grouping_key(
            alert=alert,
            rule_id=rule_id,
            source_ip=source_ip,
        )

        if not grouping_key:
            log.warning(
                "IDS incident skipped: missing grouping fields for rule=%s src=%s",
                rule_id,
                source_ip,
            )
            return

        existing = self._find_open_incident_by_key(grouping_key)

        if existing:
            self._update_ids_incident(
                hit=existing,
                alert=alert,
                rule_id=rule_id,
                story_type=story_type,
                grouping_key=grouping_key,
                ts=ts,
                now=now,
            )
        else:
            existing_retry = self._find_open_incident_by_key(grouping_key)
            if existing_retry:
                self._update_ids_incident(
                    hit=existing_retry,
                    alert=alert,
                    rule_id=rule_id,
                    story_type=story_type,
                    grouping_key=grouping_key,
                    ts=ts,
                    now=now,
                )
            else:
                self._create_ids_incident(
                    alert=alert,
                    rule_id=rule_id,
                    story_type=story_type,
                    grouping_key=grouping_key,
                    source_ip=source_ip,
                    ts=ts,
                    now=now,
                )

        self._correlate_ids_with_behavioral_incidents(
            alert=alert,
            rule_id=rule_id,
            source_ip=source_ip,
            ts=ts,
            now=now,
        )

    def _resolve_ids_story(self, rule_id: str) -> tuple[str, str]:
        """
        Return the standalone IDS incident type and compact IDS story key.
        """
        story_type = self.RULE_TO_INCIDENT_TYPE.get(
            rule_id,
            self.IDS_STORY_UNKNOWN,
        )
        story_key = _IDS_STORY_KEYS.get(rule_id, "unknown_high")
        return story_type, story_key

    def _build_ids_grouping_key(
        self,
        alert: dict,
        rule_id: str,
        source_ip: str,
    ) -> Optional[str]:
        """
        IDS standalone grouping:
            ids::<story>::src::<source_ip>::sig::<suricata_signature_id>

        If Suricata signature ID is absent, fall back to SIEM-AI rule_id so
        the incident can still be grouped without inserting fake values.
        """
        if not source_ip:
            return None

        _, story_key = self._resolve_ids_story(rule_id)
        ids_rule_id = self._extract_ids_rule_id(alert) or rule_id

        if not ids_rule_id:
            return None

        return f"ids::{story_key}::src::{source_ip}::sig::{ids_rule_id}"

    def _create_ids_incident(
        self,
        alert: dict,
        rule_id: str,
        story_type: str,
        grouping_key: str,
        source_ip: str,
        ts: datetime,
        now: datetime,
    ) -> None:
        """
        Create a standalone IDS incident document.
        """
        incident_id = hashlib.sha1(grouping_key.encode()).hexdigest()[:16]

        severity = self._compute_ids_severity(rule_id, alert=alert)
        destination = self._extract_network_destination(alert)

        attack_ctx = self._build_initial_ids_attack_context(
            alert=alert,
            rule_id=rule_id,
            story_type=story_type,
            source_ip=source_ip,
            ts=ts,
        )

        doc = {
            "incident": {
                "id": incident_id,
                "version": 1,
                "type": story_type,
                "status": "open",
                "severity": severity,
                "first_seen": self._fmt_ts(ts),
                "last_seen": self._fmt_ts(ts),
                "alert_count": 1,
                "grouping_key": grouping_key,
            },
            "source": {
                "ip": source_ip,
            },
            "destination": {
                k: v for k, v in destination.items() if v is not None
            },
            "network": {
                k: v
                for k, v in {
                    "transport": self._field(alert, "network.transport"),
                    "protocol": self._field(alert, "network.protocol"),
                }.items()
                if v is not None
            },
            "attack_context": attack_ctx,
            "related": {
                "alert_ids": self._alert_ids_from_alert(alert),
                "rule_ids": [rule_id],
                "ids_rule_ids": (
                    [self._extract_ids_rule_id(alert)]
                    if self._extract_ids_rule_id(alert)
                    else []
                ),
            },
            "created_at": self._fmt_ts(now),
            "updated_at": self._fmt_ts(now),
        }

        self.es.index(
            index=self._index_name(now),
            id=incident_id,
            body=doc,
            refresh="wait_for",
        )

        log.info(
            "🆕 IDS INCIDENT CREATED [OPEN] type=%s severity=%s src=%s key=%s rule=%s sig=%s",
            story_type,
            severity,
            source_ip,
            grouping_key,
            rule_id,
            self._extract_ids_rule_id(alert) or self._extract_ids_signature(alert),
        )
        self._run_ai_analysis(self._index_name(now), incident_id, doc)
        self._run_cross_layer_correlation()

    def _update_ids_incident(
        self,
        hit: dict,
        alert: dict,
        rule_id: str,
        story_type: str,
        grouping_key: str,
        ts: datetime,
        now: datetime,
    ) -> None:
        """
        Update a standalone IDS incident with cooldown protection.

        Cooldown is bypassed for genuinely new IDS evidence:
          - new SIEM-AI IDS rule ID
          - new Suricata signature ID
          - severity increase
        """
        src = hit["_source"]
        incident = src["incident"]

        if "attack_context" not in src or not isinstance(src["attack_context"], dict):
            src["attack_context"] = {}

        ctx = src["attack_context"]
        self._ensure_ids_attack_context(ctx)

        last_seen = self._parse_ts(incident.get("last_seen")) or now
        cooldown = self.WINDOWS.get(rule_id, {}).get("cooldown_window", 20)
        elapsed = (now - last_seen).total_seconds()

        existing_rule_ids = set(src.get("related", {}).get("rule_ids", []))
        existing_ids_rule_ids = set(src.get("related", {}).get("ids_rule_ids", []))
        existing_ids_rule_ids.update(ctx.get("ids_rule_ids_seen") or [])

        incoming_ids_rule_id = self._extract_ids_rule_id(alert)

        current_severity = incident.get("severity", "MEDIUM")
        new_severity = self._compute_ids_severity(rule_id, alert=alert, ctx=ctx)

        is_new_rule_id = rule_id not in existing_rule_ids
        is_new_ids_rule_id = bool(
            incoming_ids_rule_id and incoming_ids_rule_id not in existing_ids_rule_ids
        )
        severity_increases = self._severity_rank(new_severity) > self._severity_rank(
            current_severity
        )

        bypass_cooldown = is_new_rule_id or is_new_ids_rule_id or severity_increases

        if not bypass_cooldown and elapsed < cooldown:
            log.warning(
                "⏸️ IDS INCIDENT SKIPPED DUE TO COOLDOWN rule=%s key=%s elapsed=%.1fs cooldown=%ss sig=%s",
                rule_id,
                grouping_key,
                elapsed,
                int(cooldown),
                incoming_ids_rule_id or self._extract_ids_signature(alert),
            )
            return

        self._enrich_ids_context_from_alert(alert, rule_id, ctx, ts)

        incident["type"] = story_type
        incident["severity"] = self._compute_ids_severity(rule_id, alert=alert, ctx=ctx)
        incident["version"] = incident.get("version", 1) + 1
        incident["alert_count"] = incident.get("alert_count", 0) + 1
        incident["last_seen"] = self._fmt_ts(ts)

        source_ip = self._extract_network_source_ip(alert)
        if source_ip:
            src.setdefault("source", {})
            src["source"]["ip"] = source_ip

        destination = self._extract_network_destination(alert)
        if destination:
            src.setdefault("destination", {})
            src["destination"].update(destination)

        network_updates = {
            "transport": self._field(alert, "network.transport"),
            "protocol": self._field(alert, "network.protocol"),
        }
        clean_network_updates = {
            k: v for k, v in network_updates.items() if v is not None
        }
        if clean_network_updates:
            src.setdefault("network", {})
            src["network"].update(clean_network_updates)

        src.setdefault("related", {})
        src["related"].setdefault("alert_ids", [])
        src["related"].setdefault("rule_ids", [])
        src["related"].setdefault("ids_rule_ids", [])

        src["related"]["alert_ids"] = list(
            set(src["related"]["alert_ids"] + self._alert_ids_from_alert(alert))
        )

        if rule_id not in src["related"]["rule_ids"]:
            src["related"]["rule_ids"].append(rule_id)

        if incoming_ids_rule_id and incoming_ids_rule_id not in src["related"]["ids_rule_ids"]:
            src["related"]["ids_rule_ids"].append(incoming_ids_rule_id)

        src["updated_at"] = self._fmt_ts(now)

        self._save(hit, src)

        log.info(
            "🔄 IDS INCIDENT UPDATED key=%s type=%s severity=%s alerts=%s rule=%s sig=%s",
            grouping_key,
            incident.get("type", story_type),
            incident.get("severity", "?"),
            incident.get("alert_count", 0),
            rule_id,
            incoming_ids_rule_id or self._extract_ids_signature(alert),
        )
        self._run_ai_analysis(hit["_index"], hit["_id"], src)
        self._run_cross_layer_correlation()

    def _build_initial_ids_attack_context(
        self,
        alert: dict,
        rule_id: str,
        story_type: str,
        source_ip: str,
        ts: datetime,
    ) -> dict:
        """
        Construct the first IDS attack_context document.
        """
        ts_str = self._fmt_ts(ts)
        _, story_key = self._resolve_ids_story(rule_id)

        ctx: dict[str, Any] = {
            "layer": "network",
            "source": "suricata_ids",
            "ids_story": story_key,
            "source_ip": source_ip,
            "ids_rule_ids_seen": [],
            "ids_rule_names_seen": [],
            "ids_rule_categories_seen": [],
            "ids_severity_labels_seen": [],
            "ids_tags_seen": [],
            "ids_correlation_reasons": [],
            "destination_ips_seen": [],
            "destination_ports_seen": [],
            "first_seen": ts_str,
            "last_seen": ts_str,
            "alert_count": 0,
            "users_seen": [],
            "source_ips_seen": [source_ip] if source_ip else [],
            "hosts_seen": [],
            "primary_user": None,
            "compromised_user": None,
            "grouping_strategy": "ids_source_signature",
        }

        self._enrich_ids_context_from_alert(alert, rule_id, ctx, ts)
        return ctx

    def _ensure_ids_attack_context(self, ctx: dict) -> None:
        """
        Upgrade-safe initialization for IDS attack_context.
        """
        ctx.setdefault("layer", "network")
        ctx.setdefault("source", "suricata_ids")
        ctx.setdefault("ids_story", "unknown_high")
        ctx.setdefault("source_ip", None)
        ctx.setdefault("ids_rule_ids_seen", [])
        ctx.setdefault("ids_rule_names_seen", [])
        ctx.setdefault("ids_rule_categories_seen", [])
        ctx.setdefault("ids_severity_labels_seen", [])
        ctx.setdefault("ids_tags_seen", [])
        ctx.setdefault("ids_correlation_reasons", [])
        ctx.setdefault("destination_ips_seen", [])
        ctx.setdefault("destination_ports_seen", [])
        ctx.setdefault("first_seen", None)
        ctx.setdefault("last_seen", None)
        ctx.setdefault("alert_count", 0)
        ctx.setdefault("users_seen", [])
        ctx.setdefault("source_ips_seen", [])
        ctx.setdefault("hosts_seen", [])
        ctx.setdefault("primary_user", None)
        ctx.setdefault("compromised_user", None)
        ctx.setdefault("grouping_strategy", "ids_source_signature")

    def _enrich_ids_context_from_alert(
        self,
        alert: dict,
        rule_id: str,
        ctx: dict,
        ts: datetime,
    ) -> None:
        """
        Merge IDS evidence from one alert into attack_context.
        """
        self._ensure_ids_attack_context(ctx)

        ts_str = self._fmt_ts(ts)
        if not ctx.get("first_seen"):
            ctx["first_seen"] = ts_str
        ctx["last_seen"] = ts_str
        ctx["alert_count"] = ctx.get("alert_count", 0) + 1

        _, story_key = self._resolve_ids_story(rule_id)
        ctx["ids_story"] = story_key

        source_ip = self._extract_network_source_ip(alert)
        if source_ip:
            ctx["source_ip"] = ctx.get("source_ip") or source_ip
            ctx["source_ips_seen"] = self._bounded_merge(
                ctx.get("source_ips_seen"),
                [source_ip],
                _MAX_DEST_IPS,
            )

        ids_rule_id = self._extract_ids_rule_id(alert)
        ids_rule_name = self._extract_ids_rule_name(alert)
        ids_rule_category = self._extract_ids_rule_category(alert)
        ids_signature = self._extract_ids_signature(alert)
        ids_severity_label = self._extract_field_priority(
            alert,
            "ids.severity_label",
            "attack_context.ids_severity_label",
        )
        ids_tags = self._extract_ids_tags(alert)

        ctx["ids_rule_ids_seen"] = self._bounded_merge(
            ctx.get("ids_rule_ids_seen"),
            [ids_rule_id],
            _MAX_IDS_RULE_IDS,
        )
        ctx["ids_rule_names_seen"] = self._bounded_merge(
            ctx.get("ids_rule_names_seen"),
            [ids_rule_name, ids_signature],
            _MAX_IDS_RULE_NAMES,
        )
        ctx["ids_rule_categories_seen"] = self._bounded_merge(
            ctx.get("ids_rule_categories_seen"),
            [ids_rule_category],
            _MAX_IDS_CATEGORIES,
        )
        ctx["ids_severity_labels_seen"] = self._bounded_merge(
            ctx.get("ids_severity_labels_seen"),
            [ids_severity_label],
            _MAX_IDS_SEVERITY_LABELS,
        )
        ctx["ids_tags_seen"] = self._bounded_merge(
            ctx.get("ids_tags_seen"),
            ids_tags,
            _MAX_IDS_TAGS,
        )

        dest_ip = self._extract_field_priority(
            alert,
            "destination.ip",
            "attack_context.destination_ip",
        )
        if dest_ip:
            ctx["destination_ips_seen"] = self._bounded_merge(
                ctx.get("destination_ips_seen"),
                [dest_ip],
                _MAX_DEST_IPS,
            )

        dest_port = self._extract_field_priority(
            alert,
            "destination.port",
            "attack_context.destination_port",
        )
        if dest_port is not None:
            ctx["destination_ports_seen"] = self._bounded_merge(
                ctx.get("destination_ports_seen"),
                [str(dest_port)],
                _MAX_DEST_PORTS,
            )

        for field_key, ctx_key in (
            ("network.transport", "network_transport"),
            ("network.protocol", "network_protocol"),
            ("event.dataset", "event_dataset"),
            ("event.action", "event_action"),
            ("event.severity", "ids_severity"),
            ("ids.severity", "ids_severity"),
            ("ids.alert_action", "ids_alert_action"),
        ):
            val = self._field(alert, field_key)
            if val is not None:
                ctx[ctx_key] = val

    def _compute_ids_severity(
        self,
        rule_id: str,
        alert: Optional[dict] = None,
        ctx: Optional[dict] = None,
    ) -> str:
        """
        Compute standalone IDS incident severity.

        SIEM-AI severity is based on the IDS story/category. Suricata numeric
        severity is retained as evidence and never blindly replaces this model.
        """
        rule_ids_seen = set()

        if ctx:
            rule_ids_seen.update(ctx.get("ids_siem_rule_ids_seen") or [])
            # Compatibility: related.rule_ids may not live in ctx, so infer
            # from IDS story evidence where possible.
            stories = set(ctx.get("ids_rule_categories_seen") or [])
            tags = set(ctx.get("ids_tags_seen") or [])

            if "ids_malware" in tags:
                rule_ids_seen.add("network_ids_malware")
            if "ids_c2" in tags:
                rule_ids_seen.add("network_ids_c2")
            if "ids_exfiltration" in tags:
                rule_ids_seen.add("network_ids_exfiltration")
            if "ids_exploit" in tags:
                rule_ids_seen.add("network_ids_exploit")
            if stories:
                pass

        rule_ids_seen.add(rule_id)

        if (
            "network_ids_c2" in rule_ids_seen
            and "network_ids_malware" in rule_ids_seen
        ):
            return "CRITICAL"

        if "network_ids_exfiltration" in rule_ids_seen:
            return "CRITICAL"

        if "network_ids_c2" in rule_ids_seen:
            return "CRITICAL"

        if "network_ids_malware" in rule_ids_seen:
            return "HIGH"

        if "network_ids_exploit" in rule_ids_seen:
            return "HIGH"

        if "network_ids_credential" in rule_ids_seen:
            return "HIGH"

        if "network_ids_unknown_high" in rule_ids_seen:
            return "HIGH"

        return _IDS_DEFAULT_SEVERITY.get(rule_id, "MEDIUM")

    def _extract_ids_rule_id(self, alert: dict) -> Optional[str]:
        return self._clean_value(
            self._extract_field_priority(
                alert,
                "ids.rule_id",
                "attack_context.ids_rule_id",
                "suricata.alert.signature_id",
            )
        )

    def _extract_ids_rule_name(self, alert: dict) -> Optional[str]:
        return self._clean_value(
            self._extract_field_priority(
                alert,
                "ids.rule_name",
                "attack_context.ids_rule_name",
            )
        )

    def _extract_ids_rule_category(self, alert: dict) -> Optional[str]:
        return self._clean_value(
            self._extract_field_priority(
                alert,
                "ids.rule_category",
                "attack_context.ids_rule_category",
                "suricata.alert.category",
            )
        )

    def _extract_ids_signature(self, alert: dict) -> Optional[str]:
        return self._clean_value(
            self._extract_field_priority(
                alert,
                "ids.alert_signature",
                "attack_context.ids_alert_signature",
                "suricata.alert.signature",
                "ids.rule_name",
            )
        )

    def _extract_ids_tags(self, alert: dict) -> list[str]:
        tags = self._field(alert, "tags")
        if not tags:
            tags = self._field(alert, "attack_context.tags")

        if not tags:
            return []

        if isinstance(tags, str):
            clean = self._clean_value(tags)
            return [clean] if clean else []

        result: list[str] = []
        try:
            for tag in tags:
                clean = self._clean_value(tag)
                if clean and clean not in result:
                    result.append(clean)
        except TypeError:
            return []

        return result

    def _correlate_ids_with_behavioral_incidents(
        self,
        alert: dict,
        rule_id: str,
        source_ip: str,
        ts: datetime,
        now: datetime,
    ) -> None:
        """
        Add IDS evidence to compatible open behavioral incidents.

        Standalone IDS incidents are always handled separately before this.
        This method only enriches existing behavioral incidents when they exist.
        """
        if rule_id == "network_ids_scan_recon":
            hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_RECON,
                source_ip,
            )
            if hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_scan_recon_confirms_behavioral_recon",
                    ts=ts,
                    now=now,
                )
            return

        if rule_id == "network_ids_c2":
            c2_hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_C2,
                source_ip,
            )
            if c2_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=c2_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_c2_confirms_behavioral_c2",
                    ts=ts,
                    now=now,
                )
                return

            egress_hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_EGRESS,
                source_ip,
            )
            if egress_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=egress_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_c2_promotes_egress_to_c2",
                    ts=ts,
                    now=now,
                    promote_to_type=self.NETWORK_STORY_C2,
                )
                return

            dns_hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_DNS,
                source_ip,
            )
            if dns_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=dns_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_c2_promotes_dns_to_c2",
                    ts=ts,
                    now=now,
                    promote_to_type=self.NETWORK_STORY_C2,
                )
            return

        if rule_id == "network_ids_malware":
            c2_hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_C2,
                source_ip,
            )
            if c2_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=c2_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_malware_confirms_c2",
                    ts=ts,
                    now=now,
                )
                return

            egress_hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_EGRESS,
                source_ip,
            )
            if egress_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=egress_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_malware_promotes_egress",
                    ts=ts,
                    now=now,
                    promote_to_type=self.NETWORK_STORY_C2,
                )
                return

            dns_hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_DNS,
                source_ip,
            )
            if dns_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=dns_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_malware_confirms_dns_staging",
                    ts=ts,
                    now=now,
                )
            return

        if rule_id == "network_ids_exploit":
            recon_hit = self._find_open_incident_by_type_and_source(
                self.NETWORK_STORY_RECON,
                source_ip,
            )
            if recon_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=recon_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_exploit_after_recon",
                    ts=ts,
                    now=now,
                )

            web_hit = self._find_open_web_incident_by_source_or_destination(alert)
            if web_hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=web_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_exploit_confirms_web_attack",
                    ts=ts,
                    now=now,
                )
            return

        if rule_id == "network_ids_exfiltration":
            for incident_type, reason in (
                (self.NETWORK_STORY_EGRESS, "ids_exfiltration_confirms_egress"),
                (self.NETWORK_STORY_DNS, "ids_exfiltration_confirms_dns_tunneling"),
                (self.NETWORK_STORY_C2, "ids_exfiltration_supports_c2"),
            ):
                hit = self._find_open_incident_by_type_and_source(incident_type, source_ip)
                if hit:
                    self._update_behavioral_incident_with_ids_evidence(
                        hit=hit,
                        alert=alert,
                        rule_id=rule_id,
                        reason=reason,
                        ts=ts,
                        now=now,
                    )
            return

        if rule_id == "network_ids_credential":
            auth_hit = self._find_open_auth_incident_for_ids(alert)
            if auth_hit:
                incident_type = auth_hit.get("_source", {}).get("incident", {}).get("type")
                if incident_type == "account_compromise":
                    reason = "ids_credential_confirms_account_compromise"
                elif incident_type == "password_spray_attack":
                    reason = "ids_credential_confirms_password_spray"
                else:
                    reason = "ids_credential_confirms_bruteforce"

                self._update_behavioral_incident_with_ids_evidence(
                    hit=auth_hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason=reason,
                    ts=ts,
                    now=now,
                )
            return

        if rule_id == "network_ids_policy":
            for incident_type, reason in (
                (self.NETWORK_STORY_EGRESS, "ids_policy_confirms_suspicious_egress"),
                (self.NETWORK_STORY_C2, "ids_policy_supports_c2"),
            ):
                hit = self._find_open_incident_by_type_and_source(incident_type, source_ip)
                if hit:
                    self._update_behavioral_incident_with_ids_evidence(
                        hit=hit,
                        alert=alert,
                        rule_id=rule_id,
                        reason=reason,
                        ts=ts,
                        now=now,
                    )
                    return
            return

        if rule_id == "network_ids_protocol_anomaly":
            for incident_type, reason in (
                (self.NETWORK_STORY_EGRESS, "ids_protocol_anomaly_supports_egress"),
                (self.NETWORK_STORY_C2, "ids_protocol_anomaly_supports_c2"),
                (self.IDS_STORY_EXPLOIT, "ids_protocol_anomaly_supports_exploit"),
            ):
                hit = self._find_open_incident_by_type_and_source(incident_type, source_ip)
                if hit:
                    self._update_behavioral_incident_with_ids_evidence(
                        hit=hit,
                        alert=alert,
                        rule_id=rule_id,
                        reason=reason,
                        ts=ts,
                        now=now,
                    )
                    return
            return

        if rule_id == "network_ids_unknown_high":
            hit = self._find_first_open_incident_by_types_and_source(
                [
                    self.NETWORK_STORY_C2,
                    self.NETWORK_STORY_EGRESS,
                    self.NETWORK_STORY_DNS,
                    self.NETWORK_STORY_RECON,
                    self.WEB_MULTI_VECTOR_TYPE,
                    "Web Attack / SQL Injection",
                    "Web Attack / Path Traversal",
                    "Web Attack / XSS",
                    "Web Attack / Sensitive File Probe",
                    "account_compromise",
                    "password_spray_attack",
                    "distributed_bruteforce_attack",
                    "targeted_account_attack",
                    "brute_force_attack",
                ],
                source_ip,
            )
            if hit:
                self._update_behavioral_incident_with_ids_evidence(
                    hit=hit,
                    alert=alert,
                    rule_id=rule_id,
                    reason="ids_unknown_high_supports_existing_incident",
                    ts=ts,
                    now=now,
                )

    def _update_behavioral_incident_with_ids_evidence(
        self,
        hit: dict,
        alert: dict,
        rule_id: str,
        reason: str,
        ts: datetime,
        now: datetime,
        promote_to_type: Optional[str] = None,
    ) -> None:
        """
        Merge IDS evidence into an existing behavioral incident.
        """
        src = hit["_source"]
        incident = src["incident"]

        if "attack_context" not in src or not isinstance(src["attack_context"], dict):
            src["attack_context"] = {}

        ctx = src["attack_context"]
        self._ensure_behavioral_ids_context(ctx)

        source_ip = self._extract_network_source_ip(alert)
        ids_rule_id = self._extract_ids_rule_id(alert)
        ids_signature = self._extract_ids_signature(alert)

        old_type = incident.get("type")
        old_severity = incident.get("severity", "MEDIUM")
        new_severity = self._compute_behavioral_ids_severity(
            existing_type=old_type,
            rule_id=rule_id,
            current_severity=old_severity,
            promote_to_type=promote_to_type,
        )

        src.setdefault("related", {})
        src["related"].setdefault("alert_ids", [])
        src["related"].setdefault("rule_ids", [])
        src["related"].setdefault("ids_rule_ids", [])

        existing_rule_ids = set(src["related"].get("rule_ids") or [])
        existing_ids_rule_ids = set(src["related"].get("ids_rule_ids") or [])
        existing_ids_rule_ids.update(ctx.get("ids_rule_ids_seen") or [])

        is_new_rule_id = rule_id not in existing_rule_ids
        is_new_ids_rule_id = bool(ids_rule_id and ids_rule_id not in existing_ids_rule_ids)
        is_story_promotion = bool(promote_to_type and promote_to_type != old_type)
        severity_increases = self._severity_rank(new_severity) > self._severity_rank(
            old_severity
        )

        cooldown = self.WINDOWS.get(rule_id, {}).get("cooldown_window", 20)
        last_seen = self._parse_ts(incident.get("last_seen")) or now
        elapsed = (now - last_seen).total_seconds()

        bypass_cooldown = (
            is_new_rule_id
            or is_new_ids_rule_id
            or is_story_promotion
            or severity_increases
        )

        if not bypass_cooldown and elapsed < cooldown:
            log.warning(
                "⏸️ IDS INCIDENT SKIPPED DUE TO COOLDOWN rule=%s key=%s elapsed=%.1fs cooldown=%ss sig=%s",
                rule_id,
                incident.get("grouping_key", ""),
                elapsed,
                int(cooldown),
                ids_rule_id or ids_signature,
            )
            return

        self._merge_ids_evidence_into_context(ctx, alert, rule_id, reason, ts)

        if promote_to_type and promote_to_type != old_type:
            incident["type"] = promote_to_type
            log.info(
                "🔥 IDS CORRELATION PROMOTED %s → %s src=%s reason=%s",
                old_type,
                promote_to_type,
                source_ip,
                reason,
            )

        incident["severity"] = new_severity
        incident["version"] = incident.get("version", 1) + 1
        incident["alert_count"] = incident.get("alert_count", 0) + 1
        incident["last_seen"] = self._fmt_ts(ts)

        src["related"]["alert_ids"] = list(
            set(src["related"]["alert_ids"] + self._alert_ids_from_alert(alert))
        )

        if rule_id not in src["related"]["rule_ids"]:
            src["related"]["rule_ids"].append(rule_id)

        if ids_rule_id and ids_rule_id not in src["related"]["ids_rule_ids"]:
            src["related"]["ids_rule_ids"].append(ids_rule_id)

        src["updated_at"] = self._fmt_ts(now)

        self._save(hit, src)

        log.info(
            "🔗 IDS CORRELATION: %s updated %s src=%s sig=%s reason=%s",
            rule_id,
            incident.get("type", old_type),
            source_ip,
            ids_rule_id or ids_signature,
            reason,
        )

    def _find_open_incident_by_type_and_source(
        self,
        incident_type: str,
        source_ip: str,
    ) -> Optional[dict]:
        """
        Find one open incident by type and source.ip.
        """
        if not incident_type or not source_ip:
            return None

        q = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"incident.status.keyword": "open"}},
                        {"term": {"incident.type.keyword": incident_type}},
                        {"term": {"source.ip.keyword": source_ip}},
                    ]
                }
            },
        }

        res = self.es.search(index="siem-incidents-*", body=q)
        hits = res.get("hits", {}).get("hits", [])
        return hits[0] if hits else None

    def _find_first_open_incident_by_types_and_source(
        self,
        incident_types: list[str],
        source_ip: str,
    ) -> Optional[dict]:
        """
        Search incident types in priority order and return the first open hit.
        """
        for incident_type in incident_types:
            hit = self._find_open_incident_by_type_and_source(incident_type, source_ip)
            if hit:
                return hit
        return None

    def _find_open_web_incident_by_source_or_destination(
        self,
        alert: dict,
    ) -> Optional[dict]:
        """
        Find a compatible open web incident using IDS source/destination context.
        Defensive: returns None if no clean source/destination is available.
        """
        source_ip = self._extract_network_source_ip(alert)
        destination_ip = self._extract_field_priority(
            alert,
            "destination.ip",
            "attack_context.destination_ip",
        )

        web_types = [
            self.WEB_MULTI_VECTOR_TYPE,
            "Web Attack / SQL Injection",
            "Web Attack / Path Traversal",
            "Web Attack / XSS",
            "Web Attack / Sensitive File Probe",
            "Web Attack / Reconnaissance",
        ]

        should_terms = []
        for ip_value in (source_ip, destination_ip):
            if ip_value:
                should_terms.extend(
                    [
                        {"term": {"source.ip.keyword": ip_value}},
                        {"term": {"attack_context.attacker_ip.keyword": ip_value}},
                        {"term": {"attack_context.source_ip.keyword": ip_value}},
                    ]
                )

        if not should_terms:
            return None

        q = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"incident.status.keyword": "open"}},
                        {"terms": {"incident.type.keyword": web_types}},
                        {"bool": {"should": should_terms, "minimum_should_match": 1}},
                    ]
                }
            },
        }

        res = self.es.search(index="siem-incidents-*", body=q)
        hits = res.get("hits", {}).get("hits", [])
        return hits[0] if hits else None

    def _find_open_auth_incident_for_ids(self, alert: dict) -> Optional[dict]:
        """
        Find a compatible open auth/system incident using source.ip first and
        user.name as secondary evidence when present.
        """
        source_ip = self._extract_network_source_ip(alert)
        user = self._field(alert, "user.name")

        auth_types = [
            "account_compromise",
            "password_spray_attack",
            "distributed_bruteforce_attack",
            "targeted_account_attack",
            "brute_force_attack",
            "privilege_escalation_attempt",
        ]

        should_terms = []
        if source_ip:
            should_terms.extend(
                [
                    {"term": {"source.ip.keyword": source_ip}},
                    {"term": {"attack_context.source_ip.keyword": source_ip}},
                    {"term": {"attack_context.source_ips_seen.keyword": source_ip}},
                ]
            )

        if user:
            should_terms.extend(
                [
                    {"term": {"user.name.keyword": user}},
                    {"term": {"attack_context.primary_user.keyword": user}},
                    {"term": {"attack_context.compromised_user.keyword": user}},
                    {"term": {"attack_context.users_seen.keyword": user}},
                ]
            )

        if not should_terms:
            return None

        q = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"incident.status.keyword": "open"}},
                        {"terms": {"incident.type.keyword": auth_types}},
                        {"bool": {"should": should_terms, "minimum_should_match": 1}},
                    ]
                }
            },
        }

        res = self.es.search(index="siem-incidents-*", body=q)
        hits = res.get("hits", {}).get("hits", [])
        return hits[0] if hits else None

    def _ensure_behavioral_ids_context(self, ctx: dict) -> None:
        """
        Initialize IDS correlation evidence keys on any existing behavioral
        attack_context without disturbing its original shape.
        """
        ctx.setdefault("ids_confirmed", False)
        ctx.setdefault("ids_rule_ids_seen", [])
        ctx.setdefault("ids_rule_names_seen", [])
        ctx.setdefault("ids_rule_categories_seen", [])
        ctx.setdefault("ids_severity_labels_seen", [])
        ctx.setdefault("ids_tags_seen", [])
        ctx.setdefault("ids_correlation_reasons", [])
        ctx.setdefault("last_ids_seen", None)

    def _merge_ids_evidence_into_context(
        self,
        ctx: dict,
        alert: dict,
        rule_id: str,
        reason: str,
        ts: datetime,
    ) -> None:
        """
        Merge IDS evidence into an existing behavioral incident context.
        """
        self._ensure_behavioral_ids_context(ctx)

        ctx["ids_confirmed"] = True
        ctx["last_ids_seen"] = self._fmt_ts(ts)

        ids_rule_id = self._extract_ids_rule_id(alert)
        ids_rule_name = self._extract_ids_rule_name(alert)
        ids_signature = self._extract_ids_signature(alert)
        ids_category = self._extract_ids_rule_category(alert)
        ids_severity_label = self._extract_field_priority(
            alert,
            "ids.severity_label",
            "attack_context.ids_severity_label",
        )

        ctx["ids_rule_ids_seen"] = self._bounded_merge(
            ctx.get("ids_rule_ids_seen"),
            [ids_rule_id],
            _MAX_IDS_RULE_IDS,
        )
        ctx["ids_rule_names_seen"] = self._bounded_merge(
            ctx.get("ids_rule_names_seen"),
            [ids_rule_name, ids_signature],
            _MAX_IDS_RULE_NAMES,
        )
        ctx["ids_rule_categories_seen"] = self._bounded_merge(
            ctx.get("ids_rule_categories_seen"),
            [ids_category],
            _MAX_IDS_CATEGORIES,
        )
        ctx["ids_severity_labels_seen"] = self._bounded_merge(
            ctx.get("ids_severity_labels_seen"),
            [ids_severity_label],
            _MAX_IDS_SEVERITY_LABELS,
        )
        ctx["ids_tags_seen"] = self._bounded_merge(
            ctx.get("ids_tags_seen"),
            self._extract_ids_tags(alert),
            _MAX_IDS_TAGS,
        )
        ctx["ids_correlation_reasons"] = self._bounded_merge(
            ctx.get("ids_correlation_reasons"),
            [reason],
            _MAX_IDS_CORR_REASONS,
        )

    def _compute_behavioral_ids_severity(
        self,
        existing_type: Optional[str],
        rule_id: str,
        current_severity: str,
        promote_to_type: Optional[str] = None,
    ) -> str:
        """
        Compute severity when IDS evidence enriches a behavioral incident.
        """
        target_type = promote_to_type or existing_type
        current_rank = self._severity_rank(current_severity)

        if rule_id in {"network_ids_c2", "network_ids_exfiltration"}:
            candidate = "CRITICAL"
        elif rule_id == "network_ids_malware" and target_type == self.NETWORK_STORY_C2:
            candidate = "CRITICAL"
        elif rule_id == "network_ids_malware":
            candidate = "HIGH"
        elif rule_id == "network_ids_exploit" and (
            target_type == self.WEB_MULTI_VECTOR_TYPE
            or target_type in {
                "Web Attack / SQL Injection",
                "Web Attack / Path Traversal",
            }
        ):
            candidate = "CRITICAL"
        elif rule_id == "network_ids_exploit":
            candidate = "HIGH"
        elif rule_id == "network_ids_scan_recon" and target_type == self.NETWORK_STORY_RECON:
            candidate = "HIGH"
        elif rule_id == "network_ids_credential" and target_type == "account_compromise":
            candidate = "CRITICAL"
        elif rule_id == "network_ids_credential":
            candidate = "HIGH"
        elif rule_id == "network_ids_unknown_high":
            candidate = "HIGH"
        else:
            candidate = current_severity or "MEDIUM"

        return candidate if self._severity_rank(candidate) > current_rank else current_severity

    @staticmethod
    def _severity_rank(severity: Optional[str]) -> int:
        return {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }.get(str(severity or "").upper(), 0)

    @staticmethod
    def _clean_value(value: Any) -> Optional[str]:
        """
        Return a clean string value or None. Never returns fake placeholders.
        """
        if value is None:
            return None

        cleaned = str(value).strip()
        if not cleaned:
            return None

        if cleaned.lower() in {"n/a", "none", "null", "unknown"}:
            return None

        return cleaned

    def _bounded_merge(
        self,
        existing: Any,
        incoming: Any,
        max_items: int,
    ) -> list[str]:
        """
        Merge values into a bounded, de-duplicated list while preserving order.
        """
        merged: list[str] = []

        def add_one(value: Any) -> None:
            cleaned = self._clean_value(value)
            if cleaned and cleaned not in merged:
                merged.append(cleaned)

        if isinstance(existing, str):
            add_one(existing)
        else:
            try:
                for value in existing or []:
                    add_one(value)
            except TypeError:
                add_one(existing)

        if isinstance(incoming, str):
            add_one(incoming)
        else:
            try:
                for value in incoming or []:
                    add_one(value)
            except TypeError:
                add_one(incoming)

        return merged[:max_items]

    # =========================================================================
    # CREATE (existing — untouched)
    # =========================================================================

    def _create_incident(self, alert, rule_id, grouping_key, ts, now, user):
        incident_id = hashlib.sha1(grouping_key.encode()).hexdigest()[:16]

        src_ip = self._field(alert, "source.ip")
        host = self._field(alert, "host.name")

        is_web = rule_id in self.WEB_RULES

        if is_web:
            attack_context = self._build_initial_web_attack_context(
                alert=alert,
                rule_id=rule_id,
                src_ip=src_ip,
                host=host,
            )
            severity = self._compute_web_severity(attack_context["web_rule_ids_seen"])
            incident_type = self.RULE_TO_INCIDENT_TYPE[rule_id]
        else:
            attack_context = {
                "users_seen": [],
                "source_ips_seen": [],
                "hosts_seen": [],
                "primary_user": None,
                "compromised_user": None,
                "grouping_strategy": self._grouping_strategy(rule_id),
            }
            self._enrich_context_from_alert(alert, attack_context)
            severity = self._field(alert, "rule.severity") or "MEDIUM"
            incident_type = self.RULE_TO_INCIDENT_TYPE[rule_id]

        doc = {
            "incident": {
                "id": incident_id,
                "version": 1,
                "type": incident_type,
                "status": "open",
                "severity": severity,
                "first_seen": self._fmt_ts(ts),
                "last_seen": self._fmt_ts(ts),
                "alert_count": 1,
                "grouping_key": grouping_key,
            },
            "source": {
                "ip": src_ip,
            },
            "host": {
                "name": host,
            },
            "attack_context": attack_context,
            "related": {
                "alert_ids": self._alert_ids_from_alert(alert),
                "rule_ids": [rule_id],
            },
            "created_at": self._fmt_ts(now),
            "updated_at": self._fmt_ts(now),
        }

        self.es.index(
            index=self._index_name(now),
            id=incident_id,
            body=doc,
            refresh="wait_for",
        )

        log.info(
            "🆕 INCIDENT CREATED [OPEN] type=%s severity=%s key=%s",
            incident_type,
            severity,
            grouping_key,
        )
        self._run_ai_analysis(self._index_name(now), incident_id, doc)
        self._run_cross_layer_correlation()

    # =========================================================================
    # UPDATE (existing — untouched)
    # =========================================================================

    def _update_incident(self, hit, alert, incoming_rule_id, grouping_key, ts, now, user):
        src = hit["_source"]
        incident = src["incident"]
        is_web = incoming_rule_id in self.WEB_RULES

        if "attack_context" not in src or not isinstance(src["attack_context"], dict):
            src["attack_context"] = {}

        ctx = src["attack_context"]

        last_seen = self._parse_ts(incident.get("last_seen")) or now
        cooldown = self.WINDOWS.get(incoming_rule_id, {}).get("cooldown_window", 2)

        is_auth_escalation = (
            incoming_rule_id == "success_after_brute_force"
            and incident.get("type") in self.ESCALATABLE_TYPES
        )

        is_new_web_rule = False
        if is_web:
            self._ensure_web_attack_context(ctx)
            existing_web_rules = set(ctx.get("web_rule_ids_seen") or [])
            is_new_web_rule = incoming_rule_id not in existing_web_rules

        bypass_cooldown = is_auth_escalation or is_new_web_rule

        elapsed = (now - last_seen).total_seconds()

        if not bypass_cooldown and elapsed < cooldown:
            log.warning(
                "⏸️ INCIDENT SKIPPED DUE TO COOLDOWN rule=%s key=%s type=%s elapsed=%.2fs cooldown=%ss alert_count=%s existing_rules=%s",
                incoming_rule_id,
                grouping_key,
                incident.get("type", ""),
                elapsed,
                int(cooldown),
                incident.get("alert_count", 0),
                sorted(list(ctx.get("web_rule_ids_seen", []))) if is_web else [],
            )
            return

        if is_web:
            self._enrich_web_context_from_alert(alert, incoming_rule_id, ctx)
        else:
            self._ensure_attack_context(ctx)
            self._enrich_context_from_alert(alert, ctx)

        if is_auth_escalation:
            old_type = incident["type"]
            incident["type"] = "account_compromise"

            if user:
                ctx["compromised_user"] = user

            log.info(
                "🔥 INCIDENT ESCALATED %s → account_compromise (%s)",
                old_type,
                incident.get("grouping_key", grouping_key),
            )

        if is_web and incident.get("type") != "account_compromise":
            web_rule_ids_seen = ctx.get("web_rule_ids_seen", [])
            incident["type"] = self._compute_web_incident_type(web_rule_ids_seen)
            incident["severity"] = self._compute_web_severity(web_rule_ids_seen)

        incident["version"] = incident.get("version", 1) + 1
        incident["alert_count"] = incident.get("alert_count", 0) + 1
        incident["last_seen"] = self._fmt_ts(ts)

        src.setdefault("related", {})
        src["related"].setdefault("alert_ids", [])
        src["related"].setdefault("rule_ids", [])

        new_alert_ids = self._alert_ids_from_alert(alert)
        src["related"]["alert_ids"] = list(
            set(src["related"]["alert_ids"] + new_alert_ids)
        )

        if incoming_rule_id not in src["related"]["rule_ids"]:
            src["related"]["rule_ids"].append(incoming_rule_id)

        src["updated_at"] = self._fmt_ts(now)

        self._save(hit, src)

        log.info(
            "🔄 INCIDENT UPDATED key=%s type=%s severity=%s alerts=%s",
            incident.get("grouping_key", grouping_key),
            incident["type"],
            incident.get("severity", "?"),
            incident["alert_count"],
        )
        self._run_ai_analysis(hit["_index"], hit["_id"], src)
        self._run_cross_layer_correlation()

    # =========================================================================
    # WEB INCIDENT HELPERS (existing — untouched)
    # =========================================================================

    def _build_grouping_key(self, rule_id, alert):
        host = self._field(alert, "host.name")

        if rule_id in self.WEB_RULES:
            ip = self._field(alert, "source.ip")
            if not ip or not host:
                return None
            return f"web::ip::{ip}::host::{host}"

        if rule_id in self.USER_BASED_RULES:
            user = self._field(alert, "user.name")
            if not user or not host:
                return None
            return f"user::{user}::{host}"

        if rule_id in self.IP_BASED_RULES:
            ip = self._field(alert, "source.ip")
            if not ip or not host:
                return None
            return f"ip::{ip}::{host}"

        ip = self._field(alert, "source.ip")
        user = self._field(alert, "user.name")

        if ip and host:
            return f"ip::{ip}::{host}"
        if user and host:
            return f"user::{user}::{host}"

        return None

    def _grouping_strategy(self, rule_id):
        if rule_id in self.WEB_RULES:
            return "web_ip_host"
        if rule_id in self.USER_BASED_RULES:
            return "user"
        if rule_id in self.IP_BASED_RULES:
            return "ip"
        return "default"

    def _build_initial_web_attack_context(
        self,
        alert: dict,
        rule_id: str,
        src_ip: Optional[str],
        host: Optional[str],
    ) -> dict:
        ctx: dict[str, Any] = {
            "layers": ["web"],
            "attacker_ip": src_ip,
            "target_host": host,
            "web_rule_ids_seen": [],
            "web_attack_types_seen": [],
            "top_urls": [],
            "status_codes_seen": [],
            "user_agents_seen": [],
            "raw_event_samples": [],
            "mitre_ids_seen": [],
            "mitre_techniques_seen": [],
            "first_seen": None,
            "last_seen": None,
            "alert_count": 0,
            "users_seen": [],
            "source_ips_seen": [src_ip] if src_ip else [],
            "hosts_seen": [host] if host else [],
            "primary_user": None,
            "compromised_user": None,
            "grouping_strategy": "web_ip_host",
            "process_name": None,
        }

        self._enrich_web_context_from_alert(alert, rule_id, ctx)
        return ctx

    def _ensure_web_attack_context(self, ctx: dict) -> None:
        ctx.setdefault("layers", ["web"])
        ctx.setdefault("attacker_ip", None)
        ctx.setdefault("target_host", None)
        ctx.setdefault("web_rule_ids_seen", [])
        ctx.setdefault("web_attack_types_seen", [])
        ctx.setdefault("top_urls", [])
        ctx.setdefault("status_codes_seen", [])
        ctx.setdefault("user_agents_seen", [])
        ctx.setdefault("raw_event_samples", [])
        ctx.setdefault("mitre_ids_seen", [])
        ctx.setdefault("mitre_techniques_seen", [])
        ctx.setdefault("first_seen", None)
        ctx.setdefault("last_seen", None)
        ctx.setdefault("alert_count", 0)
        ctx.setdefault("users_seen", [])
        ctx.setdefault("source_ips_seen", [])
        ctx.setdefault("hosts_seen", [])
        ctx.setdefault("primary_user", None)
        ctx.setdefault("compromised_user", None)
        ctx.setdefault("grouping_strategy", "web_ip_host")
        ctx.setdefault("process_name", None)

        if "web" not in ctx["layers"]:
            ctx["layers"].append("web")

    def _enrich_web_context_from_alert(
        self,
        alert: dict,
        rule_id: str,
        ctx: dict,
    ) -> None:
        ts_raw = self._field(alert, "@timestamp") or self._field(alert, "evidence.first_seen")
        ts_str = ts_raw if isinstance(ts_raw, str) else None

        if rule_id and rule_id not in ctx["web_rule_ids_seen"]:
            ctx["web_rule_ids_seen"].append(rule_id)

        attack_type = self.RULE_TO_INCIDENT_TYPE.get(rule_id)
        if attack_type and attack_type not in ctx["web_attack_types_seen"]:
            ctx["web_attack_types_seen"].append(attack_type)

        if ts_str:
            if not ctx["first_seen"]:
                ctx["first_seen"] = ts_str
            ctx["last_seen"] = ts_str

        ctx["alert_count"] = ctx.get("alert_count", 0) + 1

        proc = self._field(alert, "process.name")
        if proc and not ctx.get("process_name"):
            ctx["process_name"] = proc

        ip = self._field(alert, "source.ip")
        host = self._field(alert, "host.name")
        if ip and not ctx.get("attacker_ip"):
            ctx["attacker_ip"] = ip
        if host and not ctx.get("target_host"):
            ctx["target_host"] = host

        src_ips = set(ctx.get("source_ips_seen") or [])
        hosts_set = set(ctx.get("hosts_seen") or [])
        if ip:
            src_ips.add(ip)
        if host:
            hosts_set.add(host)
        ctx["source_ips_seen"] = sorted(src_ips)
        ctx["hosts_seen"] = sorted(hosts_set)

        url = self._field(alert, "url.original")
        if url and url not in ctx["top_urls"]:
            ctx["top_urls"] = (ctx["top_urls"] + [url])[:_MAX_URLS]

        evidence_urls = self._field(alert, "evidence.top_urls") or []
        for u in evidence_urls:
            if u and u not in ctx["top_urls"] and len(ctx["top_urls"]) < _MAX_URLS:
                ctx["top_urls"].append(u)

        status = self._field(alert, "http.response.status_code")
        if status is not None:
            status_str = str(status)
            if status_str not in ctx["status_codes_seen"]:
                ctx["status_codes_seen"] = (ctx["status_codes_seen"] + [status_str])[:_MAX_STATUS_CODES]

        ua = self._field(alert, "user_agent.original")
        if ua and ua not in ctx["user_agents_seen"]:
            ctx["user_agents_seen"] = (ctx["user_agents_seen"] + [ua])[:_MAX_USER_AGENTS]

        mitre_id = self._field(alert, "mitre.id")
        mitre_technique = self._field(alert, "mitre.technique")
        mitre_tactic = self._field(alert, "mitre.tactic")

        if mitre_id:
            ids = [mitre_id] if isinstance(mitre_id, str) else list(mitre_id)
            for mid in ids:
                if mid and mid not in ctx["mitre_ids_seen"]:
                    ctx["mitre_ids_seen"] = (ctx["mitre_ids_seen"] + [mid])[:_MAX_MITRE_IDS]

        if mitre_technique:
            techs = [mitre_technique] if isinstance(mitre_technique, str) else list(mitre_technique)
            for t in techs:
                if t and t not in ctx["mitre_techniques_seen"]:
                    ctx["mitre_techniques_seen"] = (ctx["mitre_techniques_seen"] + [t])[:_MAX_MITRE_IDS]

        if mitre_tactic:
            tactics = [mitre_tactic] if isinstance(mitre_tactic, str) else list(mitre_tactic)
            ctx.setdefault("mitre_tactics_seen", [])
            for tac in tactics:
                if tac and tac not in ctx["mitre_tactics_seen"]:
                    ctx["mitre_tactics_seen"].append(tac)

        raw_events = self._field(alert, "evidence.raw_events") or []
        for line in raw_events:
            if line and line not in ctx["raw_event_samples"]:
                if len(ctx["raw_event_samples"]) < _MAX_RAW_SAMPLES:
                    ctx["raw_event_samples"].append(line)

        raw_log = self._field(alert, "raw_log") or self._field(alert, "message")
        if raw_log and raw_log not in ctx["raw_event_samples"]:
            if len(ctx["raw_event_samples"]) < _MAX_RAW_SAMPLES:
                ctx["raw_event_samples"].append(raw_log)

    def _compute_web_incident_type(self, web_rule_ids_seen: list) -> str:
        if not web_rule_ids_seen:
            return "Web Attack / Correlated Web Activity"

        if len(set(web_rule_ids_seen)) >= 2:
            return self.WEB_MULTI_VECTOR_TYPE

        return self.RULE_TO_INCIDENT_TYPE.get(
            web_rule_ids_seen[0], "Web Attack / Correlated Web Activity"
        )

    def _compute_web_severity(self, web_rule_ids_seen: list) -> str:
        if not web_rule_ids_seen:
            return "LOW"

        rule_set = set(web_rule_ids_seen)

        recon_present = bool(rule_set & WEB_RECON_RULES)
        exploit_present = bool(rule_set & WEB_EXPLOIT_RULES)
        distinct_count = len(rule_set)

        if distinct_count >= 2:
            return "CRITICAL"

        if recon_present and exploit_present:
            return "CRITICAL"

        if exploit_present:
            rule_id = next(iter(rule_set & WEB_EXPLOIT_RULES))
            if rule_id == "web_sensitive_file":
                return "MEDIUM"
            return "HIGH"

        if recon_present:
            return "LOW"

        return "MEDIUM"

    # =========================================================================
    # NON-WEB CONTEXT ENRICHMENT (existing — untouched)
    # =========================================================================

    def _ensure_attack_context(self, ctx: dict[str, Any]) -> None:
        ctx.setdefault("users_seen", [])
        ctx.setdefault("source_ips_seen", [])
        ctx.setdefault("hosts_seen", [])
        ctx.setdefault("primary_user", None)
        ctx.setdefault("compromised_user", None)
        ctx.setdefault("grouping_strategy", None)

        if not isinstance(ctx["users_seen"], list):
            ctx["users_seen"] = list(ctx["users_seen"])

        if not isinstance(ctx["source_ips_seen"], list):
            ctx["source_ips_seen"] = list(ctx["source_ips_seen"])

        if not isinstance(ctx["hosts_seen"], list):
            ctx["hosts_seen"] = list(ctx["hosts_seen"])

    def _enrich_context_from_alert(self, alert, ctx):
        self._ensure_attack_context(ctx)

        users = set(ctx.get("users_seen", []))
        source_ips = set(ctx.get("source_ips_seen", []))
        hosts = set(ctx.get("hosts_seen", []))

        direct_user = self._field(alert, "user.name")
        direct_ip = self._field(alert, "source.ip")
        direct_host = self._field(alert, "host.name")

        if direct_user:
            users.add(direct_user)

        if direct_ip:
            source_ips.add(direct_ip)

        if direct_host:
            hosts.add(direct_host)

        evidence_users = self._field(alert, "evidence.users_seen") or []
        evidence_ips = self._field(alert, "evidence.source_ips_seen") or []
        evidence_hosts = self._field(alert, "evidence.hosts_seen") or []

        correlation_users = self._field(alert, "correlation.users_seen") or []
        correlation_ips = self._field(alert, "correlation.source_ips") or []
        correlation_host = self._field(alert, "correlation.host")

        unique_users = self._field(alert, "evidence.unique_users") or []
        unique_ips = self._field(alert, "evidence.unique_ips") or []

        self._add_many(users, evidence_users)
        self._add_many(users, correlation_users)
        self._add_many(users, unique_users)

        self._add_many(source_ips, evidence_ips)
        self._add_many(source_ips, correlation_ips)
        self._add_many(source_ips, unique_ips)

        self._add_many(hosts, evidence_hosts)
        if correlation_host:
            hosts.add(str(correlation_host))

        raw_events = self._field(alert, "evidence.raw_events") or []
        for line in raw_events:
            extracted_user = self._extract_user_from_raw_log(line)
            if extracted_user:
                users.add(extracted_user)

        users.discard("")
        users.discard("unknown")
        source_ips.discard("")
        source_ips.discard("unknown")
        hosts.discard("")
        hosts.discard("unknown")

        ctx["users_seen"] = sorted(users)
        ctx["source_ips_seen"] = sorted(source_ips)
        ctx["hosts_seen"] = sorted(hosts)

        if not ctx.get("primary_user") and ctx["users_seen"]:
            ctx["primary_user"] = ctx["users_seen"][0]

    @staticmethod
    def _add_many(target: set[str], values: Any) -> None:
        if not values:
            return

        if isinstance(values, str):
            target.add(values)
            return

        try:
            for value in values:
                if value:
                    target.add(str(value))
        except TypeError:
            return

    @staticmethod
    def _extract_user_from_raw_log(line: str) -> Optional[str]:
        if not isinstance(line, str):
            return None

        marker = " for "
        if marker in line:
            try:
                part = line.split(marker, 1)[1]
                username = part.split(" ", 1)[0].strip()
                if username:
                    return username
            except Exception:
                return None

        if " : authentication failure" in line:
            try:
                username = line.split(" : authentication failure", 1)[0].split()[-1]
                if username:
                    return username
            except Exception:
                return None

        return None

    # =========================================================================
    # AUTO CLOSE (existing — untouched)
    # =========================================================================

    def _auto_close_incidents(self):
        now = self._utcnow()

        if (
            self._last_autoclose_run is not None
            and (now - self._last_autoclose_run).total_seconds() < 5
        ):
            return

        self._last_autoclose_run = now

        query = {
            "size": 100,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "incident.status.keyword": "open",
                            }
                        }
                    ]
                }
            },
        }

        resp = self.es.search(index="siem-incidents-*", body=query)

        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            incident = src["incident"]

            last_seen = self._parse_ts(incident.get("last_seen"))
            if not last_seen:
                continue

            rule_ids = src.get("related", {}).get("rule_ids", [])
            if not rule_ids:
                continue

            last_rule = rule_ids[-1]
            if last_rule not in self.WINDOWS:
                continue

            if any(r in self.WEB_RULES for r in rule_ids):
                timeout = max(
                    self.WINDOWS[r]["incident_inactivity_timeout"]
                    for r in rule_ids
                    if r in self.WINDOWS
                )
            elif any(r in NETWORK_ALL_RULES for r in rule_ids):
                # Network: use the longest timeout among contributing rules.
                # A C2 incident seeded by port_scan should live as long as C2.
                # Mirrors Wazuh: frequency rule timeout is max of contributing rules.
                timeout = max(
                    self.WINDOWS[r]["incident_inactivity_timeout"]
                    for r in rule_ids
                    if r in self.WINDOWS
                )
            elif any(r in IDS_RULE_IDS for r in rule_ids):
                # IDS: use the longest timeout among contributing IDS rules.
                timeout = max(
                    self.WINDOWS[r]["incident_inactivity_timeout"]
                    for r in rule_ids
                    if r in self.WINDOWS
                )
            else:
                timeout = self.WINDOWS[last_rule]["incident_inactivity_timeout"]

            if last_seen < now - timedelta(seconds=timeout):
                incident["status"] = "closed"
                incident["version"] = incident.get("version", 1) + 1
                src["updated_at"] = self._fmt_ts(now)

                self._save(hit, src)

                log.info("✅ INCIDENT CLOSED %s", incident.get("grouping_key"))

    # =========================================================================
    # ES HELPERS (existing — untouched)
    # =========================================================================

    def _find_open_incident_by_key(self, key):
        q = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "incident.grouping_key.keyword": key,
                            }
                        },
                        {
                            "term": {
                                "incident.status.keyword": "open",
                            }
                        },
                    ]
                }
            },
        }

        res = self.es.search(index="siem-incidents-*", body=q)
        hits = res["hits"]["hits"]

        return hits[0] if hits else None

    def _find_escalation_candidate(self, alert, user):
        host = self._field(alert, "host.name")
        ts = self._parse_ts(self._field(alert, "@timestamp"))

        if not user or not host or not ts:
            return None

        q = {
            "size": 25,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "incident.status.keyword": "open",
                            }
                        },
                        {
                            "terms": {
                                "incident.type.keyword": [
                                    "brute_force_attack",
                                    "targeted_account_attack",
                                    "password_spray_attack",
                                    "distributed_bruteforce_attack",
                                    "Web Attack / Path Traversal",
                                    "Web Attack / SQL Injection",
                                    "Web Attack / XSS",
                                    "Web Attack / Sensitive File Probe",
                                    "Web Attack / Reconnaissance",
                                    "Web Attack / Multi-Vector Web Intrusion Attempt",
                                ]
                            }
                        },
                        {
                            "term": {
                                "host.name.keyword": host,
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "term": {
                                            "attack_context.primary_user.keyword": user,
                                        }
                                    },
                                    {
                                        "term": {
                                            "attack_context.users_seen.keyword": user,
                                        }
                                    },
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            },
            "sort": [
                {"incident.last_seen": {"order": "desc"}},
                {"incident.alert_count": {"order": "desc"}},
                {"updated_at": {"order": "desc"}},
            ],
        }

        res = self.es.search(index="siem-incidents-*", body=q)

        candidates = []

        for hit in res["hits"]["hits"]:
            src = hit["_source"]
            incident = src.get("incident", {})

            first_seen = self._parse_ts(incident.get("first_seen"))
            last_seen = self._parse_ts(incident.get("last_seen"))

            if not first_seen or not last_seen:
                continue

            timeout = self.WINDOWS["success_after_brute_force"]["incident_inactivity_timeout"]

            if not (first_seen <= ts <= last_seen + timedelta(seconds=timeout)):
                continue

            score = self._score_escalation_candidate(hit, alert, user, host, ts)
            candidates.append((score, hit))

        if not candidates:
            return None

        candidates.sort(key=lambda item: item[0], reverse=True)
        best_score, best_hit = candidates[0]

        log.info(
            "Escalation candidate selected: type=%s score=%s key=%s user=%s host=%s",
            best_hit["_source"]["incident"].get("type"),
            best_score,
            best_hit["_source"]["incident"].get("grouping_key"),
            user,
            host,
        )

        return best_hit

    def _score_escalation_candidate(self, hit, alert, user, host, ts):
        src = hit["_source"]
        incident = src.get("incident", {})
        ctx = src.get("attack_context", {})

        incident_type = incident.get("type")
        score = self.INCIDENT_TYPE_PRIORITY.get(incident_type, 0)

        source_ip = self._field(alert, "source.ip")
        incident_source_ip = self._field(src, "source.ip")

        users_seen = set(ctx.get("users_seen", []))
        source_ips_seen = set(ctx.get("source_ips_seen", []))
        hosts_seen = set(ctx.get("hosts_seen", []))
        primary_user = ctx.get("primary_user")

        if user == primary_user:
            score += 30

        if user in users_seen:
            score += 40

        if host in hosts_seen:
            score += 20

        if source_ip and source_ip == incident_source_ip:
            score += 15

        if source_ip and source_ip in source_ips_seen:
            score += 15

        alert_count = incident.get("alert_count", 0)
        try:
            score += min(int(alert_count), 10)
        except Exception:
            pass

        last_seen = self._parse_ts(incident.get("last_seen"))
        if last_seen:
            age_seconds = abs((ts - last_seen).total_seconds())
            if age_seconds <= 60:
                score += 20
            elif age_seconds <= 180:
                score += 10

        return score

    # =========================================================================
    # UTILS (existing — untouched)
    # =========================================================================

    def _alert_ids_from_alert(self, alert):
        aid = self._field(alert, "alert.id")
        if isinstance(aid, str) and aid.strip():
            return [aid.strip()]

        ids = self._field(alert, "matched.event_ids")
        if isinstance(ids, list) and ids:
            out = [str(i).strip() for i in ids if i is not None and str(i).strip()]
            if out:
                return out

        es_id = alert.get("_id") if isinstance(alert, dict) else None
        if es_id is not None and str(es_id).strip():
            return [str(es_id).strip()]

        return []

    def _save(self, hit, body):
        self.es.index(
            index=hit["_index"],
            id=hit["_id"],
            body=body,
            refresh="wait_for",
        )

    def _field(self, doc, dotted):
        if not isinstance(doc, dict):
            return None

        if dotted in doc:
            return doc[dotted]

        val = doc

        for k in dotted.split("."):
            if not isinstance(val, dict):
                return None
            val = val.get(k)
            if val is None:
                return None

        return val

    def _utcnow(self):
        return datetime.now(timezone.utc)

    def _fmt_ts(self, dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    def _parse_ts(self, val):
        if not val:
            return None
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except Exception:
            return None

    def _index_name(self, dt):
        return f"{self.INCIDENT_INDEX_PREFIX}-{dt.strftime('%Y.%m.%d')}"