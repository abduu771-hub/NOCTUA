"""
detection_engine/rules.py
All rule definitions as data structures.

NO execution logic — only RuleDefinition instances.
Each rule specifies match conditions, thresholds, and MITRE metadata.
The rule_engine uses these definitions to drive detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import config


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    description: str

    # Which event.action values activate this rule
    trigger_event_types: List[str]

    # Grouping — which Event fields to build the group key from
    group_by_fields: List[str]

    # Accumulator type: "frequency", "cardinality", or "watchlist"
    accumulator_type: str

    # Only for cardinality rules — the field whose distinct values are counted
    cardinality_field: Optional[str] = None

    # Threshold configuration
    threshold: int = 1
    timeframe_seconds: int = 60
    ignore_seconds: int = 60

    # Alert metadata
    severity: str = "MEDIUM"
    severity_level: int = 5
    mitre_id: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""


# ── Rule 1: SSH Brute Force ─────────────────────────────────────────────────

RULE_SSH_BRUTEFORCE = RuleDefinition(
    rule_id="ssh_bruteforce",
    description="One IP making many failed SSH login attempts",
    trigger_event_types=["ssh_failed_login"],
    group_by_fields=["source_ip"],
    accumulator_type="frequency",
    threshold=config.THRESHOLD_SSH_BRUTEFORCE,
    timeframe_seconds=config.TIMEFRAME_SSH_BRUTEFORCE,
    ignore_seconds=config.IGNORE_SSH_BRUTEFORCE,
    severity="HIGH",
    severity_level=10,
    mitre_id="T1110",
    mitre_tactic="Credential Access",
    mitre_technique="Brute Force",
)

# ── Rule 2: Targeted User Brute Force ───────────────────────────────────────

RULE_USER_BRUTEFORCE_BY_USER = RuleDefinition(
    rule_id="user_bruteforce_by_user",
    description="One IP focusing all attempts on one specific username",
    trigger_event_types=["ssh_failed_login"],
    group_by_fields=["source_ip", "user"],
    accumulator_type="frequency",
    threshold=config.THRESHOLD_USER_BRUTEFORCE,
    timeframe_seconds=config.TIMEFRAME_USER_BRUTEFORCE,
    ignore_seconds=config.IGNORE_USER_BRUTEFORCE,
    severity="HIGH",
    severity_level=10,
    mitre_id="T1110.001",
    mitre_tactic="Credential Access",
    mitre_technique="Password Guessing",
)

# ── Rule 3: Password Spray ──────────────────────────────────────────────────

RULE_PASSWORD_SPRAY = RuleDefinition(
    rule_id="password_spray",
    description="One IP attempting login against many different usernames",
    trigger_event_types=["ssh_failed_login"],
    group_by_fields=["source_ip"],
    accumulator_type="cardinality",
    cardinality_field="user",
    threshold=config.THRESHOLD_PASSWORD_SPRAY,
    timeframe_seconds=config.TIMEFRAME_PASSWORD_SPRAY,
    ignore_seconds=config.IGNORE_PASSWORD_SPRAY,
    severity="HIGH",
    severity_level=10,
    mitre_id="T1110.003",
    mitre_tactic="Credential Access",
    mitre_technique="Password Spraying",
)

# ── Rule 4: Distributed Brute Force ─────────────────────────────────────────

RULE_DISTRIBUTED_BRUTEFORCE = RuleDefinition(
    rule_id="distributed_bruteforce",
    description="Multiple IPs all attacking the same target username",
    trigger_event_types=["ssh_failed_login"],
    group_by_fields=["user"],
    accumulator_type="cardinality",
    cardinality_field="source_ip",
    threshold=config.THRESHOLD_DISTRIBUTED_BF,
    timeframe_seconds=config.TIMEFRAME_DISTRIBUTED_BF,
    ignore_seconds=config.IGNORE_DISTRIBUTED_BF,
    severity="CRITICAL",
    severity_level=12,
    mitre_id="T1110",
    mitre_tactic="Credential Access",
    mitre_technique="Brute Force",
)

# ── Rule 5: Success After Brute Force ───────────────────────────────────────

RULE_SUCCESS_AFTER_BRUTE_FORCE = RuleDefinition(
    rule_id="success_after_brute_force",
    description="A source IP that previously triggered a brute force alert now successfully logs in",
    trigger_event_types=["ssh_success_login_password", "ssh_success_login_key"],
    group_by_fields=["source_ip"],
    accumulator_type="watchlist",
    threshold=1,
    timeframe_seconds=config.WATCH_LIST_TTL_SECONDS,
    ignore_seconds=0,
    severity="CRITICAL",
    severity_level=15,
    mitre_id="T1110+T1078",
    mitre_tactic="Credential Access",
    mitre_technique="Brute Force / Valid Accounts",
)

# ── Rule 6: Sudo Brute Force ────────────────────────────────────────────────

RULE_SUDO_BRUTEFORCE = RuleDefinition(
    rule_id="sudo_bruteforce",
    description="Repeated sudo authentication failures by the same user",
    trigger_event_types=["sudo_failed"],
    group_by_fields=["user"],
    accumulator_type="frequency",
    threshold=config.THRESHOLD_SUDO_BRUTEFORCE,
    timeframe_seconds=config.TIMEFRAME_SUDO_BRUTEFORCE,
    ignore_seconds=config.IGNORE_SUDO_BRUTEFORCE,
    severity="MEDIUM",
    severity_level=8,
    mitre_id="T1548.003",
    mitre_tactic="Privilege Escalation",
    mitre_technique="Sudo and Sudo Caching",
)

# ── Web Attack Rules ────────────────────────────────────────────────────────

RULE_WEB_PATH_TRAVERSAL = RuleDefinition(
    rule_id="web_path_traversal",
    description="Path traversal attempts indicating directory climbing (e.g. ../)",
    trigger_event_types=["web_path_traversal_attempt"],
    group_by_fields=["source_ip"],
    accumulator_type="cardinality",
    cardinality_field="url_original",
    threshold=3,
    timeframe_seconds=120,
    ignore_seconds=300,
    severity="HIGH",
    severity_level=10,
    mitre_id="T1190",
    mitre_tactic="Initial Access",
    mitre_technique="Exploit Public-Facing Application",
)

RULE_WEB_SQL_INJECTION = RuleDefinition(
    rule_id="web_sql_injection",
    description="SQL injection attempts indicating database exploitation",
    trigger_event_types=["web_sql_injection_attempt"],
    group_by_fields=["source_ip"],
    accumulator_type="cardinality",
    cardinality_field="url_original",
    threshold=3,
    timeframe_seconds=120,
    ignore_seconds=300,
    severity="CRITICAL",
    severity_level=12,
    mitre_id="T1190",
    mitre_tactic="Initial Access",
    mitre_technique="Exploit Public-Facing Application",
)

RULE_WEB_XSS = RuleDefinition(
    rule_id="web_xss",
    description="Cross-site scripting (XSS) attempts indicating client-side payload injection",
    trigger_event_types=["web_xss_attempt"],
    group_by_fields=["source_ip"],
    accumulator_type="cardinality",
    cardinality_field="url_original",
    threshold=3,
    timeframe_seconds=120,
    ignore_seconds=300,
    severity="HIGH",
    severity_level=10,
    mitre_id="T1190",
    mitre_tactic="Initial Access",
    mitre_technique="Exploit Public-Facing Application",
)

RULE_WEB_SENSITIVE_FILE = RuleDefinition(
    rule_id="web_sensitive_file",
    description="Probes for sensitive files (e.g. .env, wp-config.php)",
    trigger_event_types=["web_sensitive_file_probe"],
    group_by_fields=["source_ip"],
    accumulator_type="cardinality",
    cardinality_field="url_original",
    threshold=3,
    timeframe_seconds=120,
    ignore_seconds=300,
    severity="MEDIUM",
    severity_level=8,
    mitre_id="T1190",
    mitre_tactic="Initial Access",
    mitre_technique="Exploit Public-Facing Application",
)

RULE_WEB_404_SCANNING = RuleDefinition(
    rule_id="web_404_scanning",
    description="High rate of 404 Not Found responses indicating dirbusting or vulnerability scanning",
    trigger_event_types=["web_404"],
    group_by_fields=["source_ip"],
    accumulator_type="frequency",
    threshold=20,
    timeframe_seconds=60,
    ignore_seconds=300,
    severity="LOW",
    severity_level=4,
    mitre_id="T1595.002",
    mitre_tactic="Reconnaissance",
    mitre_technique="Active Scanning: Vulnerability Scanning",
)

# ── Network Attack Rules ─────────────────────────────────────────────────────

RULE_NETWORK_PORT_SCAN = RuleDefinition(
    rule_id="network_port_scan",
    description="One source IP connecting to many destination ports on the same destination IP",
    trigger_event_types=["network_flow"],
    group_by_fields=["source_ip", "destination_ip"],
    accumulator_type="cardinality",
    cardinality_field="destination_port",
    threshold=10,
    timeframe_seconds=60,
    ignore_seconds=300,
    severity="MEDIUM",
    severity_level=6,
    mitre_id="T1046",
    mitre_tactic="Discovery",
    mitre_technique="Network Service Discovery",
)

RULE_NETWORK_INTERNAL_SWEEP = RuleDefinition(
    rule_id="network_internal_sweep",
    description="One source IP connecting to many internal destination IPs on the same destination port",
    trigger_event_types=["network_flow"],
    group_by_fields=["source_ip", "destination_port"],
    accumulator_type="cardinality",
    cardinality_field="destination_ip",
    threshold=8,
    timeframe_seconds=120,
    ignore_seconds=300,
    severity="MEDIUM",
    severity_level=7,
    mitre_id="T1018",
    mitre_tactic="Discovery",
    mitre_technique="Remote System Discovery",
)

RULE_NETWORK_SUSPICIOUS_OUTBOUND = RuleDefinition(
    rule_id="network_suspicious_outbound",
    description="Internal host connecting outbound to suspicious external destination ports",
    trigger_event_types=["network_suspicious_outbound"],
    group_by_fields=["source_ip", "destination_ip", "destination_port"],
    accumulator_type="frequency",
    cardinality_field=None,
    threshold=1,
    timeframe_seconds=60,
    ignore_seconds=300,
    severity="HIGH",
    severity_level=10,
    mitre_id="T1071",
    mitre_tactic="Command and Control",
    mitre_technique="Application Layer Protocol",
)

RULE_NETWORK_C2_BEACONING = RuleDefinition(
    rule_id="network_c2_beaconing",
    description="Repeated connections from one source IP to the same destination IP and port, indicating possible beaconing",
    trigger_event_types=["network_flow"],
    group_by_fields=["source_ip", "destination_ip", "destination_port"],
    accumulator_type="frequency",
    cardinality_field=None,
    threshold=8,
    timeframe_seconds=300,
    ignore_seconds=600,
    severity="HIGH",
    severity_level=11,
    mitre_id="T1071",
    mitre_tactic="Command and Control",
    mitre_technique="Application Layer Protocol",
)

RULE_NETWORK_SUSPICIOUS_DNS = RuleDefinition(
    rule_id="network_suspicious_dns",
    description="Suspicious DNS query patterns such as malware-like domains, C2-like names, or random long domains",
    trigger_event_types=["network_suspicious_dns"],
    group_by_fields=["source_ip"],
    accumulator_type="cardinality",
    cardinality_field="dns_question_name",
    threshold=3,
    timeframe_seconds=120,
    ignore_seconds=300,
    severity="MEDIUM",
    severity_level=7,
    mitre_id="T1071.004",
    mitre_tactic="Command and Control",
    mitre_technique="Application Layer Protocol: DNS",
)

# ── Ordered list of all rules ────────────────────────────────────────────────
# success_after_brute_force is evaluated separately in rule_engine.py
# but we include it here so ALL_RULES is the single source of truth.

ALL_RULES: List[RuleDefinition] = [
    RULE_SSH_BRUTEFORCE,
    RULE_USER_BRUTEFORCE_BY_USER,
    RULE_PASSWORD_SPRAY,
    RULE_DISTRIBUTED_BRUTEFORCE,
    RULE_SUCCESS_AFTER_BRUTE_FORCE,
    RULE_SUDO_BRUTEFORCE,
    RULE_WEB_PATH_TRAVERSAL,
    RULE_WEB_SQL_INJECTION,
    RULE_WEB_XSS,
    RULE_WEB_SENSITIVE_FILE,
    RULE_WEB_404_SCANNING,
    RULE_NETWORK_PORT_SCAN,
    RULE_NETWORK_INTERNAL_SWEEP,
    RULE_NETWORK_SUSPICIOUS_OUTBOUND,
    RULE_NETWORK_C2_BEACONING,
    RULE_NETWORK_SUSPICIOUS_DNS,
]
