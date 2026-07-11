# SIEM-AI Technical Inventory

## Folder: /

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./pnpm-lock.yaml

**Purpose:** Configuration file (YAML).
**Inputs:** User/System defined settings.
**Outputs:** Config values consumed by application.
**Dependencies:** Application parser.
**Execution flow:** Parsed during initialization.

### File: ./ossec.conf

**Purpose:** Configuration file.
**Inputs:** System settings.
**Outputs:** Config values.
**Dependencies:** Application requiring conf.
**Execution flow:** Read at startup.

### File: ./package.json

**Purpose:** Data/Configuration file (JSON).
**Inputs:** JSON structure.
**Outputs:** Data consumed by app/package manager.
**Dependencies:** System parsing JSON.
**Execution flow:** Parsed when required.

### File: ./api_documentation.md

**Purpose:** Markdown documentation.
**Inputs:** Text content.
**Outputs:** Rendered documentation.
**Dependencies:** Markdown viewer.
**Execution flow:** Read by user.

### File: ./README.md

**Purpose:** Markdown documentation.
**Inputs:** Text content.
**Outputs:** Rendered documentation.
**Dependencies:** Markdown viewer.
**Execution flow:** Read by user.

### File: ./file_list.json

**Purpose:** Data/Configuration file (JSON).
**Inputs:** JSON structure.
**Outputs:** Data consumed by app/package manager.
**Dependencies:** System parsing JSON.
**Execution flow:** Parsed when required.

### File: ./.gitignore

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./out2.json

**Purpose:** Data/Configuration file (JSON).
**Inputs:** JSON structure.
**Outputs:** Data consumed by app/package manager.
**Dependencies:** System parsing JSON.
**Execution flow:** Parsed when required.

### File: ./filebeat.yml

**Purpose:** Configuration file (YAML).
**Inputs:** User/System defined settings.
**Outputs:** Config values consumed by application.
**Dependencies:** Application parser.
**Execution flow:** Parsed during initialization.

### File: ./docker-compose.yml

**Purpose:** Configuration file (YAML).
**Inputs:** User/System defined settings.
**Outputs:** Config values consumed by application.
**Dependencies:** Application parser.
**Execution flow:** Parsed during initialization.

### File: ./engine_state.json

**Purpose:** Data/Configuration file (JSON).
**Inputs:** JSON structure.
**Outputs:** Data consumed by app/package manager.
**Dependencies:** System parsing JSON.
**Execution flow:** Parsed when required.

### File: ./incident_engine_updated.py

**Purpose:** detection_engine/incident_engine.py

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
**Inputs:** IncidentEngine.__init__(self, es_client); IncidentEngine.process_alert(self, alert); IncidentEngine._process_network_alert(self, alert, rule_id); IncidentEngine._resolve_network_story(self, rule_id, source_ip); IncidentEngine._correlate_network(self, rule_id, source_ip, initial_story, initial_key, alert, now); IncidentEngine._create_network_incident(self, alert, rule_id, story_type, grouping_key, source_ip, ts, now); IncidentEngine._update_network_incident(self, hit, alert, rule_id, final_type, grouping_key, ts, now); IncidentEngine._build_initial_network_attack_context(self, alert, rule_id, story_type, source_ip, destination, dns_name, ts); IncidentEngine._ensure_network_attack_context(self, ctx); IncidentEngine._enrich_network_context_from_alert(self, alert, rule_id, ctx, ts); IncidentEngine._compute_network_severity(self, rule_id, story_type, alert, ctx); IncidentEngine._network_story_priority(self, story_type); IncidentEngine._story_to_machine_key(self, story_type); IncidentEngine._extract_network_source_ip(self, alert); IncidentEngine._extract_network_destination(self, alert); IncidentEngine._extract_network_dns_name(self, alert); IncidentEngine._extract_field_priority(self, alert); IncidentEngine._process_ids_alert(self, alert, rule_id); IncidentEngine._resolve_ids_story(self, rule_id); IncidentEngine._build_ids_grouping_key(self, alert, rule_id, source_ip); IncidentEngine._create_ids_incident(self, alert, rule_id, story_type, grouping_key, source_ip, ts, now); IncidentEngine._update_ids_incident(self, hit, alert, rule_id, story_type, grouping_key, ts, now); IncidentEngine._build_initial_ids_attack_context(self, alert, rule_id, story_type, source_ip, ts); IncidentEngine._ensure_ids_attack_context(self, ctx); IncidentEngine._enrich_ids_context_from_alert(self, alert, rule_id, ctx, ts); IncidentEngine._compute_ids_severity(self, rule_id, alert, ctx); IncidentEngine._extract_ids_rule_id(self, alert); IncidentEngine._extract_ids_rule_name(self, alert); IncidentEngine._extract_ids_rule_category(self, alert); IncidentEngine._extract_ids_signature(self, alert); IncidentEngine._extract_ids_tags(self, alert); IncidentEngine._correlate_ids_with_behavioral_incidents(self, alert, rule_id, source_ip, ts, now); IncidentEngine._update_behavioral_incident_with_ids_evidence(self, hit, alert, rule_id, reason, ts, now, promote_to_type); IncidentEngine._find_open_incident_by_type_and_source(self, incident_type, source_ip); IncidentEngine._find_first_open_incident_by_types_and_source(self, incident_types, source_ip); IncidentEngine._find_open_web_incident_by_source_or_destination(self, alert); IncidentEngine._find_open_auth_incident_for_ids(self, alert); IncidentEngine._ensure_behavioral_ids_context(self, ctx); IncidentEngine._merge_ids_evidence_into_context(self, ctx, alert, rule_id, reason, ts); IncidentEngine._compute_behavioral_ids_severity(self, existing_type, rule_id, current_severity, promote_to_type); IncidentEngine._severity_rank(severity); IncidentEngine._clean_value(value); IncidentEngine._bounded_merge(self, existing, incoming, max_items); IncidentEngine._create_incident(self, alert, rule_id, grouping_key, ts, now, user); IncidentEngine._update_incident(self, hit, alert, incoming_rule_id, grouping_key, ts, now, user); IncidentEngine._build_grouping_key(self, rule_id, alert); IncidentEngine._grouping_strategy(self, rule_id); IncidentEngine._build_initial_web_attack_context(self, alert, rule_id, src_ip, host); IncidentEngine._ensure_web_attack_context(self, ctx); IncidentEngine._enrich_web_context_from_alert(self, alert, rule_id, ctx); IncidentEngine._compute_web_incident_type(self, web_rule_ids_seen); IncidentEngine._compute_web_severity(self, web_rule_ids_seen); IncidentEngine._ensure_attack_context(self, ctx); IncidentEngine._enrich_context_from_alert(self, alert, ctx); IncidentEngine._add_many(target, values); IncidentEngine._extract_user_from_raw_log(line); IncidentEngine._auto_close_incidents(self); IncidentEngine._find_open_incident_by_key(self, key); IncidentEngine._find_escalation_candidate(self, alert, user); IncidentEngine._score_escalation_candidate(self, hit, alert, user, host, ts); IncidentEngine._alert_ids_from_alert(self, alert); IncidentEngine._save(self, hit, body); IncidentEngine._field(self, doc, dotted); IncidentEngine._utcnow(self); IncidentEngine._fmt_ts(self, dt); IncidentEngine._parse_ts(self, val); IncidentEngine._index_name(self, dt)
**Outputs:** IncidentEngine._resolve_network_story -> tuple[str, str]; IncidentEngine._correlate_network -> tuple[Optional[str], Optional[str]]; IncidentEngine._build_initial_network_attack_context -> dict; IncidentEngine._compute_network_severity -> str; IncidentEngine._network_story_priority -> int; IncidentEngine._story_to_machine_key -> str; IncidentEngine._extract_network_source_ip -> Optional[str]; IncidentEngine._extract_network_destination -> dict; IncidentEngine._extract_network_dns_name -> Optional[str]; IncidentEngine._extract_field_priority -> Any; IncidentEngine._resolve_ids_story -> tuple[str, str]; IncidentEngine._build_ids_grouping_key -> Optional[str]; IncidentEngine._build_initial_ids_attack_context -> dict; IncidentEngine._compute_ids_severity -> str; IncidentEngine._extract_ids_rule_id -> Optional[str]; IncidentEngine._extract_ids_rule_name -> Optional[str]; IncidentEngine._extract_ids_rule_category -> Optional[str]; IncidentEngine._extract_ids_signature -> Optional[str]; IncidentEngine._extract_ids_tags -> list[str]; IncidentEngine._find_open_incident_by_type_and_source -> Optional[dict]; IncidentEngine._find_first_open_incident_by_types_and_source -> Optional[dict]; IncidentEngine._find_open_web_incident_by_source_or_destination -> Optional[dict]; IncidentEngine._find_open_auth_incident_for_ids -> Optional[dict]; IncidentEngine._compute_behavioral_ids_severity -> str; IncidentEngine._severity_rank -> int; IncidentEngine._clean_value -> Optional[str]; IncidentEngine._bounded_merge -> list[str]; IncidentEngine._build_initial_web_attack_context -> dict; IncidentEngine._compute_web_incident_type -> str; IncidentEngine._compute_web_severity -> str; IncidentEngine._extract_user_from_raw_log -> Optional[str]
**Dependencies:** __future__.annotations, hashlib, logging, datetime.datetime, datetime.timedelta, datetime.timezone, typing.Any, typing.Optional, elasticsearch.Elasticsearch
**Execution flow:** Class IncidentEngine defines method __init__. Class IncidentEngine defines method process_alert. Class IncidentEngine defines method _process_network_alert. Class IncidentEngine defines method _resolve_network_story. Class IncidentEngine defines method _correlate_network. Class IncidentEngine defines method _create_network_incident. Class IncidentEngine defines method _update_network_incident. Class IncidentEngine defines method _build_initial_network_attack_context. Class IncidentEngine defines method _ensure_network_attack_context. Class IncidentEngine defines method _enrich_network_context_from_alert. Class IncidentEngine defines method _compute_network_severity. Class IncidentEngine defines method _network_story_priority. Class IncidentEngine defines method _story_to_machine_key. Class IncidentEngine defines method _extract_network_source_ip. Class IncidentEngine defines method _extract_network_destination. Class IncidentEngine defines method _extract_network_dns_name. Class IncidentEngine defines method _extract_field_priority. Class IncidentEngine defines method _process_ids_alert. Class IncidentEngine defines method _resolve_ids_story. Class IncidentEngine defines method _build_ids_grouping_key. Class IncidentEngine defines method _create_ids_incident. Class IncidentEngine defines method _update_ids_incident. Class IncidentEngine defines method _build_initial_ids_attack_context. Class IncidentEngine defines method _ensure_ids_attack_context. Class IncidentEngine defines method _enrich_ids_context_from_alert. Class IncidentEngine defines method _compute_ids_severity. Class IncidentEngine defines method _extract_ids_rule_id. Class IncidentEngine defines method _extract_ids_rule_name. Class IncidentEngine defines method _extract_ids_rule_category. Class IncidentEngine defines method _extract_ids_signature. Class IncidentEngine defines method _extract_ids_tags. Class IncidentEngine defines method _correlate_ids_with_behavioral_incidents. Class IncidentEngine defines method _update_behavioral_incident_with_ids_evidence. Class IncidentEngine defines method _find_open_incident_by_type_and_source. Class IncidentEngine defines method _find_first_open_incident_by_types_and_source. Class IncidentEngine defines method _find_open_web_incident_by_source_or_destination. Class IncidentEngine defines method _find_open_auth_incident_for_ids. Class IncidentEngine defines method _ensure_behavioral_ids_context. Class IncidentEngine defines method _merge_ids_evidence_into_context. Class IncidentEngine defines method _compute_behavioral_ids_severity. Class IncidentEngine defines method _severity_rank. Class IncidentEngine defines method _clean_value. Class IncidentEngine defines method _bounded_merge. Class IncidentEngine defines method _create_incident. Class IncidentEngine defines method _update_incident. Class IncidentEngine defines method _build_grouping_key. Class IncidentEngine defines method _grouping_strategy. Class IncidentEngine defines method _build_initial_web_attack_context. Class IncidentEngine defines method _ensure_web_attack_context. Class IncidentEngine defines method _enrich_web_context_from_alert. Class IncidentEngine defines method _compute_web_incident_type. Class IncidentEngine defines method _compute_web_severity. Class IncidentEngine defines method _ensure_attack_context. Class IncidentEngine defines method _enrich_context_from_alert. Class IncidentEngine defines method _add_many. Class IncidentEngine defines method _extract_user_from_raw_log. Class IncidentEngine defines method _auto_close_incidents. Class IncidentEngine defines method _find_open_incident_by_key. Class IncidentEngine defines method _find_escalation_candidate. Class IncidentEngine defines method _score_escalation_candidate. Class IncidentEngine defines method _alert_ids_from_alert. Class IncidentEngine defines method _save. Class IncidentEngine defines method _field. Class IncidentEngine defines method _utcnow. Class IncidentEngine defines method _fmt_ts. Class IncidentEngine defines method _parse_ts. Class IncidentEngine defines method _index_name.

### File: ./logstash.conf

**Purpose:** Configuration file.
**Inputs:** System settings.
**Outputs:** Config values.
**Dependencies:** Application requiring conf.
**Execution flow:** Read at startup.

### File: ./test_deepseek_json.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** os, json, openai.OpenAI
**Execution flow:** Sequential execution of module level code.

### File: ./test_engine.py

**Purpose:** Python source file.
**Inputs:** make_web_event(action, url, status, ip, agent, host)
**Outputs:** None
**Dependencies:** sys, os, datetime.datetime, datetime.timezone, detection_engine.models.Event, detection_engine.rule_engine.RuleEngine
**Execution flow:** Function make_web_event defined.

### File: ./engine_state.backup-before-network-test.json

**Purpose:** Data/Configuration file (JSON).
**Inputs:** JSON structure.
**Outputs:** Data consumed by app/package manager.
**Dependencies:** System parsing JSON.
**Execution flow:** Parsed when required.

### File: ./out.json

**Purpose:** Data/Configuration file (JSON).
**Inputs:** JSON structure.
**Outputs:** Data consumed by app/package manager.
**Dependencies:** System parsing JSON.
**Execution flow:** Parsed when required.

## Folder: ./detection

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./detection/engine.py

**Purpose:** Python source file.
**Inputs:** kw(field); _es_terms_agg(must_terms, range_start, range_end, exists_fields, agg_field, agg_name, sub_agg, size); _fingerprint(parts); _fingerprint_hourly(anchor_ts, rule_name); _is_suppressed(client, fingerprint, suppress_minutes); _emit_alert(rule_name, severity, title, details, fingerprint, src_ip, user_name, suppress_minutes); detect_ssh_bruteforce_by_ip(anchor_ts); detect_password_spray_by_ip(anchor_ts); detect_user_bruteforce_by_user(anchor_ts); detect_distributed_bruteforce_by_user(anchor_ts); detect_sudo_bruteforce_by_user(anchor_ts); detect_ssh_success_after_failures(anchor_ts)
**Outputs:** get_client -> Elasticsearch; kw -> str; _es_terms_agg -> list; _fingerprint -> str; _fingerprint_hourly -> str; _is_suppressed -> bool; _emit_alert -> bool; get_anchor_timestamp -> datetime; detect_ssh_bruteforce_by_ip -> dict; detect_password_spray_by_ip -> dict; detect_user_bruteforce_by_user -> dict; detect_distributed_bruteforce_by_user -> dict; detect_sudo_bruteforce_by_user -> dict; detect_ssh_success_after_failures -> dict
**Dependencies:** hashlib, os, datetime.datetime, datetime.timedelta, datetime.timezone, typing.Optional, elasticsearch.Elasticsearch
**Execution flow:** Function get_client defined. Function kw defined. Function _es_terms_agg defined. Function _fingerprint defined. Function _fingerprint_hourly defined. Function _is_suppressed defined. Function _emit_alert defined. Function get_anchor_timestamp defined. Function detect_ssh_bruteforce_by_ip defined. Function detect_password_spray_by_ip defined. Function detect_user_bruteforce_by_user defined. Function detect_distributed_bruteforce_by_user defined. Function detect_sudo_bruteforce_by_user defined. Function detect_ssh_success_after_failures defined. Function main defined.

## Folder: ./detection_engine

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./detection_engine/elastic_client.py

**Purpose:** detection_engine/elastic_client.py
Handles ALL communication with Elasticsearch for reading events.

Responsibilities:
  - Fetch events from siem-raw-* where tags contains "ready_for_detection"
  - Checkpoint extraction

MUST NOT contain detection logic.
MUST NOT aggregate on raw text fields — always use .keyword suffix.
**Inputs:** ESReader.__init__(self, es_client, index_pattern); ESReader.poll(self, last_processed_id, last_processed_timestamp, batch_size); ESReader.get_last_checkpoint(hits)
**Outputs:** ESReader.poll -> List[dict]; ESReader.get_last_checkpoint -> Tuple[Optional[str], Optional[str]]
**Dependencies:** __future__.annotations, logging, typing.List, typing.Optional, typing.Tuple, elasticsearch.Elasticsearch, .config
**Execution flow:** Class ESReader defines method __init__. Class ESReader defines method poll. Class ESReader defines method get_last_checkpoint.

### File: ./detection_engine/accumulator.py

**Purpose:** detection_engine/accumulator.py
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
  - destination_ips_seen → all destination IPs observed in this slot/window

This allows rule_engine.py to build success-after-brute-force correlation
using user.name + host.name without depending on same source.ip.
**Inputs:** AccumulatorManager.__init__(self); AccumulatorManager.process(self, event, rule); AccumulatorManager.cleanup(self); AccumulatorManager.get_snapshot(self); AccumulatorManager._add_context(self, slot, event); AccumulatorManager._prune_context_if_possible(self, slot, rule); AccumulatorManager._build_group_key(self, event, rule); AccumulatorManager._get_group_by_field(event, field_name); AccumulatorManager._get_cardinality_field(event, field_name)
**Outputs:** AccumulatorManager.process -> Optional[AccumulatorSlot]; AccumulatorManager.get_snapshot -> dict; AccumulatorManager._build_group_key -> Optional[str]; AccumulatorManager._get_group_by_field -> Optional[str]; AccumulatorManager._get_cardinality_field -> Optional[str]
**Dependencies:** __future__.annotations, time, dataclasses.dataclass, dataclasses.field, typing.Dict, typing.List, typing.Optional, typing.Set, typing.Tuple, models.Event, rules.RuleDefinition
**Execution flow:** Class AccumulatorManager defines method __init__. Class AccumulatorManager defines method process. Class AccumulatorManager defines method cleanup. Class AccumulatorManager defines method get_snapshot. Class AccumulatorManager defines method _add_context. Class AccumulatorManager defines method _prune_context_if_possible. Class AccumulatorManager defines method _build_group_key. Class AccumulatorManager defines method _get_group_by_field. Class AccumulatorManager defines method _get_cardinality_field.

### File: ./detection_engine/config.py

**Purpose:** detection_engine/config.py
All constants and configuration values for the detection engine.
No logic — only values.
**Inputs:** None
**Outputs:** None
**Dependencies:** os
**Execution flow:** Sequential execution of module level code.

### File: ./detection_engine/alert_validator.py

**Purpose:** detection_engine/alert_validator.py
Validates alert documents before they are sent to Elasticsearch.

If validation fails:
  - the alert is NOT sent to ES
  - the validation error is logged
  - the failed alert is written to logs/invalid_alerts.jsonl

Never raises — returns (is_valid, error_message).
**Inputs:** _deep_get(d, dotted_key, default); _is_valid_iso8601(value); _is_valid_ip(value); validate_alert(alert); _scan_forbidden(obj, path, errors); _write_invalid(alert, error)
**Outputs:** _is_valid_iso8601 -> bool; _is_valid_ip -> bool; validate_alert -> Tuple[bool, Optional[str]]
**Dependencies:** __future__.annotations, ipaddress, json, logging, os, datetime.datetime, typing.Optional, typing.Tuple, .config
**Execution flow:** Function _deep_get defined. Function _is_valid_iso8601 defined. Function _is_valid_ip defined. Function validate_alert defined. Function _scan_forbidden defined. Function _write_invalid defined.

### File: ./detection_engine/lifecycle_contract.py

**Purpose:** detection_engine/lifecycle_contract.py

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
**Inputs:** is_valid_transition(current, requested); derive_incident_status(alert_statuses)
**Outputs:** is_valid_transition -> bool; derive_incident_status -> str
**Dependencies:** __future__.annotations
**Execution flow:** Function is_valid_transition defined. Function derive_incident_status defined.

### File: ./detection_engine/ai_incident_analyzer.py

**Purpose:** Python source file.
**Inputs:** AIIncidentAnalyzer.__init__(self, es_client, model); AIIncidentAnalyzer.is_enabled(self); AIIncidentAnalyzer.should_analyze(self, incident_doc, force); AIIncidentAnalyzer.build_incident_payload(self, incident_doc); AIIncidentAnalyzer.build_prompt(self, payload); AIIncidentAnalyzer.call_deepseek(self, messages); AIIncidentAnalyzer.validate_ai_analysis(self, analysis); AIIncidentAnalyzer._clean_timeline(self, value); AIIncidentAnalyzer._clean_attack_chain(self, value); AIIncidentAnalyzer.analyze_incident(self, incident_doc, force); AIIncidentAnalyzer.write_ai_analysis(self, index, doc_id, ai_analysis); AIIncidentAnalyzer.analyze_and_update(self, index, doc_id, incident_doc, force); AIIncidentAnalyzer.analyze_latest_high_or_critical(self, force); AIIncidentAnalyzer._build_evidence(self, payload); AIIncidentAnalyzer._extract_alerts_for_timeline(self, incident_doc); AIIncidentAnalyzer._add_evidence(self, evidence, label, value); AIIncidentAnalyzer._extract_related_values(self, related, keys, max_items); AIIncidentAnalyzer._flatten_to_strings(self, value); AIIncidentAnalyzer._compact_dict(self, value, max_keys, max_list_items); AIIncidentAnalyzer._clean_string_list(self, value); AIIncidentAnalyzer._clean_string(self, value, default); AIIncidentAnalyzer._first_present(self); AIIncidentAnalyzer._limited_value(self, value, max_items); AIIncidentAnalyzer._as_dict(self, value); AIIncidentAnalyzer._string(self, value); AIIncidentAnalyzer._bool(self, value); AIIncidentAnalyzer._missing(self, value); AIIncidentAnalyzer._dedupe(self, values); AIIncidentAnalyzer._humanize_key(self, key)
**Outputs:** AIIncidentAnalyzer.is_enabled -> bool; AIIncidentAnalyzer.should_analyze -> bool; AIIncidentAnalyzer.build_incident_payload -> Dict[str, Any]; AIIncidentAnalyzer.build_prompt -> List[Dict[str, str]]; AIIncidentAnalyzer.call_deepseek -> Dict[str, Any]; AIIncidentAnalyzer.validate_ai_analysis -> Dict[str, Any]; AIIncidentAnalyzer._clean_timeline -> List[Dict[str, str]]; AIIncidentAnalyzer._clean_attack_chain -> List[Dict[str, str]]; AIIncidentAnalyzer.analyze_incident -> Optional[Dict[str, Any]]; AIIncidentAnalyzer.write_ai_analysis -> bool; AIIncidentAnalyzer.analyze_and_update -> bool; AIIncidentAnalyzer.analyze_latest_high_or_critical -> bool; AIIncidentAnalyzer._build_evidence -> List[str]; AIIncidentAnalyzer._extract_alerts_for_timeline -> List[Dict[str, Any]]; AIIncidentAnalyzer._extract_related_values -> List[str]; AIIncidentAnalyzer._flatten_to_strings -> List[str]; AIIncidentAnalyzer._compact_dict -> Dict[str, Any]; AIIncidentAnalyzer._clean_string_list -> List[str]; AIIncidentAnalyzer._clean_string -> str; AIIncidentAnalyzer._first_present -> Any; AIIncidentAnalyzer._limited_value -> Any; AIIncidentAnalyzer._as_dict -> Dict[str, Any]; AIIncidentAnalyzer._string -> str; AIIncidentAnalyzer._bool -> bool; AIIncidentAnalyzer._missing -> bool; AIIncidentAnalyzer._dedupe -> List[str]; AIIncidentAnalyzer._humanize_key -> str
**Dependencies:** __future__.annotations, json, logging, os, datetime.datetime, datetime.timezone, typing.Any, typing.Dict, typing.List, typing.Optional, openai.OpenAI, lifecycle_contract.INCIDENT_STATUS_CLOSED
**Execution flow:** Class AIIncidentAnalyzer defines method __init__. Class AIIncidentAnalyzer defines method is_enabled. Class AIIncidentAnalyzer defines method should_analyze. Class AIIncidentAnalyzer defines method build_incident_payload. Class AIIncidentAnalyzer defines method build_prompt. Class AIIncidentAnalyzer defines method call_deepseek. Class AIIncidentAnalyzer defines method validate_ai_analysis. Class AIIncidentAnalyzer defines method _clean_timeline. Class AIIncidentAnalyzer defines method _clean_attack_chain. Class AIIncidentAnalyzer defines method analyze_incident. Class AIIncidentAnalyzer defines method write_ai_analysis. Class AIIncidentAnalyzer defines method analyze_and_update. Class AIIncidentAnalyzer defines method analyze_latest_high_or_critical. Class AIIncidentAnalyzer defines method _build_evidence. Class AIIncidentAnalyzer defines method _extract_alerts_for_timeline. Class AIIncidentAnalyzer defines method _add_evidence. Class AIIncidentAnalyzer defines method _extract_related_values. Class AIIncidentAnalyzer defines method _flatten_to_strings. Class AIIncidentAnalyzer defines method _compact_dict. Class AIIncidentAnalyzer defines method _clean_string_list. Class AIIncidentAnalyzer defines method _clean_string. Class AIIncidentAnalyzer defines method _first_present. Class AIIncidentAnalyzer defines method _limited_value. Class AIIncidentAnalyzer defines method _as_dict. Class AIIncidentAnalyzer defines method _string. Class AIIncidentAnalyzer defines method _bool. Class AIIncidentAnalyzer defines method _missing. Class AIIncidentAnalyzer defines method _dedupe. Class AIIncidentAnalyzer defines method _humanize_key.

### File: ./detection_engine/incident_engine.py

**Purpose:** detection_engine/incident_engine.py

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
**Inputs:** IncidentEngine.__init__(self, es_client); IncidentEngine._run_cross_layer_correlation(self); IncidentEngine._run_ai_analysis(self, index, doc_id, incident_doc); IncidentEngine.process_alert(self, alert); IncidentEngine._process_network_alert(self, alert, rule_id); IncidentEngine._resolve_network_story(self, rule_id, source_ip); IncidentEngine._correlate_network(self, rule_id, source_ip, initial_story, initial_key, alert, now); IncidentEngine._create_network_incident(self, alert, rule_id, story_type, grouping_key, source_ip, ts, now); IncidentEngine._update_network_incident(self, hit, alert, rule_id, final_type, grouping_key, ts, now); IncidentEngine._build_initial_network_attack_context(self, alert, rule_id, story_type, source_ip, destination, dns_name, ts); IncidentEngine._ensure_network_attack_context(self, ctx); IncidentEngine._enrich_network_context_from_alert(self, alert, rule_id, ctx, ts); IncidentEngine._compute_network_severity(self, rule_id, story_type, alert, ctx); IncidentEngine._network_story_priority(self, story_type); IncidentEngine._story_to_machine_key(self, story_type); IncidentEngine._extract_network_source_ip(self, alert); IncidentEngine._extract_network_destination(self, alert); IncidentEngine._extract_network_dns_name(self, alert); IncidentEngine._extract_field_priority(self, alert); IncidentEngine._process_ids_alert(self, alert, rule_id); IncidentEngine._resolve_ids_story(self, rule_id); IncidentEngine._build_ids_grouping_key(self, alert, rule_id, source_ip); IncidentEngine._create_ids_incident(self, alert, rule_id, story_type, grouping_key, source_ip, ts, now); IncidentEngine._update_ids_incident(self, hit, alert, rule_id, story_type, grouping_key, ts, now); IncidentEngine._build_initial_ids_attack_context(self, alert, rule_id, story_type, source_ip, ts); IncidentEngine._ensure_ids_attack_context(self, ctx); IncidentEngine._enrich_ids_context_from_alert(self, alert, rule_id, ctx, ts); IncidentEngine._compute_ids_severity(self, rule_id, alert, ctx); IncidentEngine._extract_ids_rule_id(self, alert); IncidentEngine._extract_ids_rule_name(self, alert); IncidentEngine._extract_ids_rule_category(self, alert); IncidentEngine._extract_ids_signature(self, alert); IncidentEngine._extract_ids_tags(self, alert); IncidentEngine._correlate_ids_with_behavioral_incidents(self, alert, rule_id, source_ip, ts, now); IncidentEngine._update_behavioral_incident_with_ids_evidence(self, hit, alert, rule_id, reason, ts, now, promote_to_type); IncidentEngine._find_open_incident_by_type_and_source(self, incident_type, source_ip); IncidentEngine._find_first_open_incident_by_types_and_source(self, incident_types, source_ip); IncidentEngine._find_open_web_incident_by_source_or_destination(self, alert); IncidentEngine._find_open_auth_incident_for_ids(self, alert); IncidentEngine._ensure_behavioral_ids_context(self, ctx); IncidentEngine._merge_ids_evidence_into_context(self, ctx, alert, rule_id, reason, ts); IncidentEngine._compute_behavioral_ids_severity(self, existing_type, rule_id, current_severity, promote_to_type); IncidentEngine._severity_rank(severity); IncidentEngine._clean_value(value); IncidentEngine._bounded_merge(self, existing, incoming, max_items); IncidentEngine._build_incident_name(self, incident_type, alert, grouping_key, attack_context); IncidentEngine._create_incident(self, alert, rule_id, grouping_key, ts, now, user); IncidentEngine._update_incident(self, hit, alert, incoming_rule_id, grouping_key, ts, now, user); IncidentEngine._build_grouping_key(self, rule_id, alert); IncidentEngine._grouping_strategy(self, rule_id); IncidentEngine._build_initial_web_attack_context(self, alert, rule_id, src_ip, host); IncidentEngine._ensure_web_attack_context(self, ctx); IncidentEngine._enrich_web_context_from_alert(self, alert, rule_id, ctx); IncidentEngine._compute_web_incident_type(self, web_rule_ids_seen); IncidentEngine._compute_web_severity(self, web_rule_ids_seen); IncidentEngine._ensure_attack_context(self, ctx); IncidentEngine._enrich_context_from_alert(self, alert, ctx); IncidentEngine._add_many(target, values); IncidentEngine._extract_user_from_raw_log(line); IncidentEngine._sync_incident_lifecycle_from_alerts(self, incident_doc, now); IncidentEngine.run_auto_close_cycle(self); IncidentEngine._find_open_incident_by_key(self, key); IncidentEngine._freeze_incident(self, hit); IncidentEngine._find_escalation_candidate(self, alert, user); IncidentEngine._score_escalation_candidate(self, hit, alert, user, host, ts); IncidentEngine._alert_ids_from_alert(self, alert); IncidentEngine._save(self, hit, body); IncidentEngine._field(self, doc, dotted); IncidentEngine._utcnow(self); IncidentEngine._fmt_ts(self, dt); IncidentEngine._parse_ts(self, val); IncidentEngine._index_name(self, dt)
**Outputs:** IncidentEngine._resolve_network_story -> tuple[str, str]; IncidentEngine._correlate_network -> tuple[Optional[str], Optional[str]]; IncidentEngine._build_initial_network_attack_context -> dict; IncidentEngine._compute_network_severity -> str; IncidentEngine._network_story_priority -> int; IncidentEngine._story_to_machine_key -> str; IncidentEngine._extract_network_source_ip -> Optional[str]; IncidentEngine._extract_network_destination -> dict; IncidentEngine._extract_network_dns_name -> Optional[str]; IncidentEngine._extract_field_priority -> Any; IncidentEngine._resolve_ids_story -> tuple[str, str]; IncidentEngine._build_ids_grouping_key -> Optional[str]; IncidentEngine._build_initial_ids_attack_context -> dict; IncidentEngine._compute_ids_severity -> str; IncidentEngine._extract_ids_rule_id -> Optional[str]; IncidentEngine._extract_ids_rule_name -> Optional[str]; IncidentEngine._extract_ids_rule_category -> Optional[str]; IncidentEngine._extract_ids_signature -> Optional[str]; IncidentEngine._extract_ids_tags -> list[str]; IncidentEngine._find_open_incident_by_type_and_source -> Optional[dict]; IncidentEngine._find_first_open_incident_by_types_and_source -> Optional[dict]; IncidentEngine._find_open_web_incident_by_source_or_destination -> Optional[dict]; IncidentEngine._find_open_auth_incident_for_ids -> Optional[dict]; IncidentEngine._compute_behavioral_ids_severity -> str; IncidentEngine._severity_rank -> int; IncidentEngine._clean_value -> Optional[str]; IncidentEngine._bounded_merge -> list[str]; IncidentEngine._build_initial_web_attack_context -> dict; IncidentEngine._compute_web_incident_type -> str; IncidentEngine._compute_web_severity -> str; IncidentEngine._extract_user_from_raw_log -> Optional[str]; IncidentEngine._sync_incident_lifecycle_from_alerts -> dict
**Dependencies:** __future__.annotations, hashlib, logging, datetime.datetime, datetime.timedelta, datetime.timezone, typing.Any, typing.Optional, unittest.result, elasticsearch.Elasticsearch, lifecycle_contract.derive_incident_status, lifecycle_contract.INCIDENT_STATUS_OPEN, lifecycle_contract.INCIDENT_STATUS_CLOSED, lifecycle_contract.derive_incident_status, lifecycle_contract.INCIDENT_STATUS_OPEN, lifecycle_contract.INCIDENT_STATUS_CLOSED, lifecycle_contract.DEFAULT_CORRELATION_WINDOW_SECONDS, lifecycle_contract.INCIDENT_SILENCE_THRESHOLD_SECONDS, lifecycle_contract.INCIDENT_LIFECYCLE_ACTIVE, lifecycle_contract.INCIDENT_LIFECYCLE_FROZEN, lifecycle_contract.INCIDENT_LIFECYCLE_CLOSED
**Execution flow:** Class IncidentEngine defines method __init__. Class IncidentEngine defines method _run_cross_layer_correlation. Class IncidentEngine defines method _run_ai_analysis. Class IncidentEngine defines method process_alert. Class IncidentEngine defines method _process_network_alert. Class IncidentEngine defines method _resolve_network_story. Class IncidentEngine defines method _correlate_network. Class IncidentEngine defines method _create_network_incident. Class IncidentEngine defines method _update_network_incident. Class IncidentEngine defines method _build_initial_network_attack_context. Class IncidentEngine defines method _ensure_network_attack_context. Class IncidentEngine defines method _enrich_network_context_from_alert. Class IncidentEngine defines method _compute_network_severity. Class IncidentEngine defines method _network_story_priority. Class IncidentEngine defines method _story_to_machine_key. Class IncidentEngine defines method _extract_network_source_ip. Class IncidentEngine defines method _extract_network_destination. Class IncidentEngine defines method _extract_network_dns_name. Class IncidentEngine defines method _extract_field_priority. Class IncidentEngine defines method _process_ids_alert. Class IncidentEngine defines method _resolve_ids_story. Class IncidentEngine defines method _build_ids_grouping_key. Class IncidentEngine defines method _create_ids_incident. Class IncidentEngine defines method _update_ids_incident. Class IncidentEngine defines method _build_initial_ids_attack_context. Class IncidentEngine defines method _ensure_ids_attack_context. Class IncidentEngine defines method _enrich_ids_context_from_alert. Class IncidentEngine defines method _compute_ids_severity. Class IncidentEngine defines method _extract_ids_rule_id. Class IncidentEngine defines method _extract_ids_rule_name. Class IncidentEngine defines method _extract_ids_rule_category. Class IncidentEngine defines method _extract_ids_signature. Class IncidentEngine defines method _extract_ids_tags. Class IncidentEngine defines method _correlate_ids_with_behavioral_incidents. Class IncidentEngine defines method _update_behavioral_incident_with_ids_evidence. Class IncidentEngine defines method _find_open_incident_by_type_and_source. Class IncidentEngine defines method _find_first_open_incident_by_types_and_source. Class IncidentEngine defines method _find_open_web_incident_by_source_or_destination. Class IncidentEngine defines method _find_open_auth_incident_for_ids. Class IncidentEngine defines method _ensure_behavioral_ids_context. Class IncidentEngine defines method _merge_ids_evidence_into_context. Class IncidentEngine defines method _compute_behavioral_ids_severity. Class IncidentEngine defines method _severity_rank. Class IncidentEngine defines method _clean_value. Class IncidentEngine defines method _bounded_merge. Class IncidentEngine defines method _build_incident_name. Class IncidentEngine defines method _create_incident. Class IncidentEngine defines method _update_incident. Class IncidentEngine defines method _build_grouping_key. Class IncidentEngine defines method _grouping_strategy. Class IncidentEngine defines method _build_initial_web_attack_context. Class IncidentEngine defines method _ensure_web_attack_context. Class IncidentEngine defines method _enrich_web_context_from_alert. Class IncidentEngine defines method _compute_web_incident_type. Class IncidentEngine defines method _compute_web_severity. Class IncidentEngine defines method _ensure_attack_context. Class IncidentEngine defines method _enrich_context_from_alert. Class IncidentEngine defines method _add_many. Class IncidentEngine defines method _extract_user_from_raw_log. Class IncidentEngine defines method _sync_incident_lifecycle_from_alerts. Class IncidentEngine defines method run_auto_close_cycle. Class IncidentEngine defines method _find_open_incident_by_key. Class IncidentEngine defines method _freeze_incident. Class IncidentEngine defines method _find_escalation_candidate. Class IncidentEngine defines method _score_escalation_candidate. Class IncidentEngine defines method _alert_ids_from_alert. Class IncidentEngine defines method _save. Class IncidentEngine defines method _field. Class IncidentEngine defines method _utcnow. Class IncidentEngine defines method _fmt_ts. Class IncidentEngine defines method _parse_ts. Class IncidentEngine defines method _index_name.

### File: ./detection_engine/cross_layer_engine.py

**Purpose:** detection_engine/cross_layer_engine.py

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
**Inputs:** _IncidentView.__init__(self, hit); _IncidentView._source(self); _IncidentView._incident(self); _IncidentView._ctx(self); _IncidentView._related(self); _IncidentView.doc_id(self); _IncidentView.doc_index(self); _IncidentView.incident_id(self); _IncidentView.incident_type(self); _IncidentView.status(self); _IncidentView.severity(self); _IncidentView.grouping_key(self); _IncidentView.is_cross_layer(self); _IncidentView.layer(self); _IncidentView.first_seen(self); _IncidentView.last_seen(self); _IncidentView.source_ip(self); _IncidentView.host_name(self); _IncidentView.user_name(self); _IncidentView.destination_ip(self); _IncidentView.source_ips_seen(self); _IncidentView.hosts_seen(self); _IncidentView.users_seen(self); _IncidentView.destination_ips_seen(self); _IncidentView.destination_ports_seen(self); _IncidentView.related_alert_ids(self); _IncidentView.related_rule_ids(self); CrossLayerEngine.__init__(self, es_client); CrossLayerEngine._run_ai_analysis(self, index, doc_id, incident_doc); CrossLayerEngine._run_n8n_notification(self, index, doc_id, incident_doc, ai_analysis); CrossLayerEngine.process_recent_open_incidents(self); CrossLayerEngine._group_layer_incidents_by_source_ip(self, incidents); CrossLayerEngine._fetch_recent_open_incidents(self); CrossLayerEngine._evaluate_standard_rule(self, rule, incidents); CrossLayerEngine._evaluate_multi_layer(self, rule, incidents); CrossLayerEngine._evaluate_full_kill_chain(self, rule, layer_incidents, existing_cross); CrossLayerEngine._share_identity(self, a, b); CrossLayerEngine._within_window(self, a, b, window_minutes); CrossLayerEngine._create_or_update_cross_layer(self, rule, matched_incidents); CrossLayerEngine._build_grouping_key(self, rule_id, incidents); CrossLayerEngine._compute_severity(self, rule, incidents); CrossLayerEngine._merge_evidence(self, incidents); CrossLayerEngine._build_evidence_summary(incident_type, evidence, reason); CrossLayerEngine._create_new(self, rule, grouping_key, severity, evidence, reasons, matched_incidents); CrossLayerEngine._update_existing(self, hit, rule, severity, evidence, reasons, matched_incidents); CrossLayerEngine._find_open_cross_layer_by_key(self, grouping_key); CrossLayerEngine._index_name(self, dt); _classify_layer(incident_type); _sev_rank(severity); _deep(doc, dotted); _parse_ts(val); _fmt_ts(dt); _as_list(val); _merge_unique(existing, incoming)
**Outputs:** _IncidentView._source -> Dict[str, Any]; _IncidentView._incident -> Dict[str, Any]; _IncidentView._ctx -> Dict[str, Any]; _IncidentView._related -> Dict[str, Any]; _IncidentView.doc_id -> str; _IncidentView.doc_index -> str; _IncidentView.incident_id -> str; _IncidentView.incident_type -> str; _IncidentView.status -> str; _IncidentView.severity -> str; _IncidentView.grouping_key -> str; _IncidentView.is_cross_layer -> bool; _IncidentView.layer -> Optional[str]; _IncidentView.first_seen -> Optional[datetime]; _IncidentView.last_seen -> Optional[datetime]; _IncidentView.source_ip -> Optional[str]; _IncidentView.host_name -> Optional[str]; _IncidentView.user_name -> Optional[str]; _IncidentView.destination_ip -> Optional[str]; _IncidentView.source_ips_seen -> Set[str]; _IncidentView.hosts_seen -> Set[str]; _IncidentView.users_seen -> Set[str]; _IncidentView.destination_ips_seen -> Set[str]; _IncidentView.destination_ports_seen -> List[str]; _IncidentView.related_alert_ids -> List[str]; _IncidentView.related_rule_ids -> List[str]; CrossLayerEngine._run_ai_analysis -> bool; CrossLayerEngine._group_layer_incidents_by_source_ip -> Dict[str, List[_IncidentView]]; CrossLayerEngine._fetch_recent_open_incidents -> List[_IncidentView]; CrossLayerEngine._share_identity -> bool; CrossLayerEngine._within_window -> bool; CrossLayerEngine._build_grouping_key -> Optional[str]; CrossLayerEngine._compute_severity -> str; CrossLayerEngine._merge_evidence -> Dict[str, Any]; CrossLayerEngine._build_evidence_summary -> str; CrossLayerEngine._find_open_cross_layer_by_key -> Optional[Dict[str, Any]]; CrossLayerEngine._index_name -> str; CrossLayerEngine._utcnow -> datetime; _classify_layer -> Optional[str]; _sev_rank -> int; _deep -> Any; _parse_ts -> Optional[datetime]; _fmt_ts -> Optional[str]; _as_list -> List[str]; _merge_unique -> List[str]
**Dependencies:** __future__.annotations, hashlib, logging, datetime.datetime, datetime.timedelta, datetime.timezone, typing.Any, typing.Dict, typing.List, typing.Optional, typing.Set, typing.Tuple, elasticsearch.Elasticsearch
**Execution flow:** Class _IncidentView defines method __init__. Class _IncidentView defines method _source. Class _IncidentView defines method _incident. Class _IncidentView defines method _ctx. Class _IncidentView defines method _related. Class _IncidentView defines method doc_id. Class _IncidentView defines method doc_index. Class _IncidentView defines method incident_id. Class _IncidentView defines method incident_type. Class _IncidentView defines method status. Class _IncidentView defines method severity. Class _IncidentView defines method grouping_key. Class _IncidentView defines method is_cross_layer. Class _IncidentView defines method layer. Class _IncidentView defines method first_seen. Class _IncidentView defines method last_seen. Class _IncidentView defines method source_ip. Class _IncidentView defines method host_name. Class _IncidentView defines method user_name. Class _IncidentView defines method destination_ip. Class _IncidentView defines method source_ips_seen. Class _IncidentView defines method hosts_seen. Class _IncidentView defines method users_seen. Class _IncidentView defines method destination_ips_seen. Class _IncidentView defines method destination_ports_seen. Class _IncidentView defines method related_alert_ids. Class _IncidentView defines method related_rule_ids. Class CrossLayerEngine defines method __init__. Class CrossLayerEngine defines method _run_ai_analysis. Class CrossLayerEngine defines method _run_n8n_notification. Class CrossLayerEngine defines method process_recent_open_incidents. Class CrossLayerEngine defines method _group_layer_incidents_by_source_ip. Class CrossLayerEngine defines method _fetch_recent_open_incidents. Class CrossLayerEngine defines method _evaluate_standard_rule. Class CrossLayerEngine defines method _evaluate_multi_layer. Class CrossLayerEngine defines method _evaluate_full_kill_chain. Class CrossLayerEngine defines method _share_identity. Class CrossLayerEngine defines method _within_window. Class CrossLayerEngine defines method _create_or_update_cross_layer. Class CrossLayerEngine defines method _build_grouping_key. Class CrossLayerEngine defines method _compute_severity. Class CrossLayerEngine defines method _merge_evidence. Class CrossLayerEngine defines method _build_evidence_summary. Class CrossLayerEngine defines method _create_new. Class CrossLayerEngine defines method _update_existing. Class CrossLayerEngine defines method _find_open_cross_layer_by_key. Class CrossLayerEngine defines method _index_name. Class CrossLayerEngine defines method _utcnow. Function _classify_layer defined. Function _sev_rank defined. Function _deep defined. Function _parse_ts defined. Function _fmt_ts defined. Function _as_list defined. Function _merge_unique defined.

### File: ./detection_engine/state.py

**Purpose:** detection_engine/state.py
Engine state persistence — survives restarts without reprocessing events.

Stores:
  - last_processed_id / last_processed_timestamp (ES checkpoint)
  - total_events_processed / total_alerts_fired (counters)
  - watch_list_snapshot (active watches)

Uses atomic write (temp file + os.replace) to prevent corruption.
MUST NOT evaluate rules.
**Inputs:** StateManager.__init__(self, state_file); StateManager._load(self); StateManager.save(self, last_id, last_timestamp, events_processed, alerts_fired, watch_list_snapshot); StateManager.last_processed_id(self); StateManager.last_processed_timestamp(self); StateManager.watch_list_snapshot(self)
**Outputs:** StateManager._load -> dict; StateManager.last_processed_id -> Optional[str]; StateManager.last_processed_timestamp -> Optional[str]; StateManager.watch_list_snapshot -> dict; StateManager._empty_state -> dict
**Dependencies:** __future__.annotations, json, logging, os, datetime.datetime, datetime.timezone, typing.Optional, .config
**Execution flow:** Class StateManager defines method __init__. Class StateManager defines method _load. Class StateManager defines method save. Class StateManager defines method last_processed_id. Class StateManager defines method last_processed_timestamp. Class StateManager defines method watch_list_snapshot. Class StateManager defines method _empty_state.

### File: ./detection_engine/alert_builder.py

**Purpose:** detection_engine/alert_builder.py
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
**Inputs:** _is_present(value); _is_network_rule(rule_id); _is_ids_rule(rule_id); _get_event_value(event, attr_name); _set_nested_if_present(document, path, value); _normalize_user_name(value); _extract_web_fields(raw_log); _sorted_string_list(value); _slot_context_list(fired_slot, attr_name); _cardinality_values(fired_slot); _latest_raw_event(raw_events, triggering_event); _apply_network_alert_fields(alert, rule, fired_slot, triggering_event, event_count, source_ips_seen, destination_ips_seen, first_seen, last_seen); _apply_ids_alert_fields(alert, rule, fired_slot, triggering_event, event_count, source_ips_seen, destination_ips_seen, first_seen, last_seen); build_alert(rule, fired_slot, triggering_event, watch_entry); _build_description(rule, event, count, unique_users, unique_ips, watch_entry)
**Outputs:** _is_present -> bool; _is_network_rule -> bool; _is_ids_rule -> bool; _get_event_value -> Any; _normalize_user_name -> Optional[str]; _extract_web_fields -> tuple[Optional[str], Optional[int], Optional[str]]; _sorted_string_list -> List[str]; _slot_context_list -> List[str]; _cardinality_values -> List[str]; _latest_raw_event -> Optional[str]; build_alert -> dict; _build_description -> str
**Dependencies:** __future__.annotations, logging, uuid, datetime.datetime, datetime.timezone, typing.Any, typing.List, typing.Optional, models.Event, rules.RuleDefinition, lifecycle_contract.ALERT_STATUS_OPEN, lifecycle_contract.DEFAULT_CORRELATION_WINDOW_SECONDS
**Execution flow:** Function _is_present defined. Function _is_network_rule defined. Function _is_ids_rule defined. Function _get_event_value defined. Function _set_nested_if_present defined. Function _normalize_user_name defined. Function _extract_web_fields defined. Function _sorted_string_list defined. Function _slot_context_list defined. Function _cardinality_values defined. Function _latest_raw_event defined. Function _apply_network_alert_fields defined. Function _apply_ids_alert_fields defined. Function build_alert defined. Function _build_description defined.

### File: ./detection_engine/rules.py

**Purpose:** detection_engine/rules.py
All rule definitions as data structures.

NO execution logic — only RuleDefinition instances.
Each rule specifies match conditions, thresholds, and MITRE metadata.
The rule_engine uses these definitions to drive detection.
**Inputs:** None
**Outputs:** None
**Dependencies:** __future__.annotations, dataclasses.dataclass, dataclasses.field, typing.List, typing.Optional, .config
**Execution flow:** Sequential execution of module level code.

### File: ./detection_engine/notification_bus.py

**Purpose:** detection_engine/notification_bus.py

Minimal in-process pub/sub for live incident notifications.

No new index, no new external dependency. The incident_engine pushes
events here; the FastAPI SSE endpoint drains them. Nothing else needs
to know this file exists.
**Inputs:** NotificationBus.__init__(self); NotificationBus.bind_loop(self, loop); NotificationBus.subscribe(self); NotificationBus.unsubscribe(self, q); NotificationBus.publish(self, event); NotificationBus._put_nowait_safe(q, event)
**Outputs:** NotificationBus.subscribe -> asyncio.Queue
**Dependencies:** asyncio, logging, datetime.datetime, datetime.timezone, typing.Any
**Execution flow:** Class NotificationBus defines method __init__. Class NotificationBus defines method bind_loop. Class NotificationBus defines method subscribe. Class NotificationBus defines method unsubscribe. Class NotificationBus defines method publish. Class NotificationBus defines method _put_nowait_safe.

### File: ./detection_engine/rule_engine.py

**Purpose:** detection_engine/rule_engine.py
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
**Inputs:** AllowlistChecker.__init__(self, ips, cidrs, users); AllowlistChecker.is_allowed(self, event); WatchList.__init__(self, ttl_seconds); WatchList._make_key(self, parent_rule, host, users_seen, source_ips); WatchList.add(self, source_ip, parent_rule, users_seen, host, failed_count); WatchList.check_success(self, source_ip, user, host); WatchList.cleanup(self); WatchList.to_dict(self); WatchList.from_dict(self, data); NetworkClassifier.classify(self, event); NetworkClassifier._is_suspicious_dns(self, name); RuleEngine.__init__(self); RuleEngine._users_from_slot(self, slot, event); RuleEngine._should_skip_due_to_precedence(self, rule_id, fired_rule_ids); RuleEngine._should_add_to_watchlist(self, rule_id, fired_rule_ids); RuleEngine._get_effective_event_types(self, event); RuleEngine._process_ids_event(self, event); RuleEngine.process_event(self, event); RuleEngine.cleanup(self); _is_private_ip(ip_value); _is_ids_rule(rule_id); _get_ids_rule_ids_for_event(event)
**Outputs:** AllowlistChecker.is_allowed -> bool; WatchList._make_key -> str; WatchList.check_success -> Optional[WatchListEntry]; WatchList.to_dict -> dict; NetworkClassifier.classify -> NetworkClassification; NetworkClassifier._is_suspicious_dns -> bool; RuleEngine._users_from_slot -> List[str]; RuleEngine._should_skip_due_to_precedence -> bool; RuleEngine._should_add_to_watchlist -> bool; RuleEngine._get_effective_event_types -> Optional[Set[str]]; RuleEngine._process_ids_event -> List[dict]; RuleEngine.process_event -> List[dict]; _is_private_ip -> bool; _is_ids_rule -> bool; _get_ids_rule_ids_for_event -> Set[str]
**Dependencies:** __future__.annotations, ipaddress, logging, re, time, dataclasses.dataclass, typing.Dict, typing.List, typing.Optional, typing.Set, .config, accumulator.AccumulatorManager, accumulator.AccumulatorSlot, alert_builder.build_alert, models.Event, rules.ALL_RULES, rules.RULE_SUCCESS_AFTER_BRUTE_FORCE, rules.RuleDefinition
**Execution flow:** Class AllowlistChecker defines method __init__. Class AllowlistChecker defines method is_allowed. Class WatchList defines method __init__. Class WatchList defines method _make_key. Class WatchList defines method add. Class WatchList defines method check_success. Class WatchList defines method cleanup. Class WatchList defines method to_dict. Class WatchList defines method from_dict. Class NetworkClassifier defines method classify. Class NetworkClassifier defines method _is_suspicious_dns. Class RuleEngine defines method __init__. Class RuleEngine defines method _users_from_slot. Class RuleEngine defines method _should_skip_due_to_precedence. Class RuleEngine defines method _should_add_to_watchlist. Class RuleEngine defines method _get_effective_event_types. Class RuleEngine defines method _process_ids_event. Class RuleEngine defines method process_event. Class RuleEngine defines method cleanup. Function _is_private_ip defined. Function _is_ids_rule defined. Function _get_ids_rule_ids_for_event defined.

### File: ./detection_engine/alert_writer.py

**Purpose:** detection_engine/alert_writer.py
Writes alert documents to Elasticsearch.

Responsibilities:
  - Receive already-built alert documents
  - Validate via alert_validator before indexing
  - Write valid alerts to siem-alerts-YYYY.MM.dd
  - Buffer failed ES writes to logs/alerts_buffer.jsonl

MUST NOT create alert content — that is alert_builder's job.
MUST NOT evaluate rules.
MUST NOT insert "N/A" values.
**Inputs:** AlertWriter.__init__(self, es_client, index_prefix, buffer_path); AlertWriter._index_name(self); AlertWriter.write(self, alert); AlertWriter.flush_buffer(self); AlertWriter._buffer_to_disk(self, alert)
**Outputs:** AlertWriter._index_name -> str; AlertWriter.write -> Optional[str]
**Dependencies:** __future__.annotations, copy, json, logging, os, datetime.datetime, datetime.timezone, typing.Optional, elasticsearch.Elasticsearch, .config, alert_validator.validate_alert, lifecycle_contract.ALERT_STATUS_OPEN
**Execution flow:** Class AlertWriter defines method __init__. Class AlertWriter defines method _index_name. Class AlertWriter defines method write. Class AlertWriter defines method flush_buffer. Class AlertWriter defines method _buffer_to_disk.

### File: ./detection_engine/automation_notifier.py

**Purpose:** Python source file.
**Inputs:** AutomationNotifier.__init__(self, webhook_url, timeout_seconds); AutomationNotifier.is_enabled(self); AutomationNotifier.build_payload(self, index, doc_id, incident_doc, ai_analysis); AutomationNotifier.notify(self, index, doc_id, incident_doc, ai_analysis)
**Outputs:** AutomationNotifier.is_enabled -> bool; AutomationNotifier.build_payload -> Dict[str, Any]; AutomationNotifier.notify -> bool
**Dependencies:** __future__.annotations, json, logging, os, urllib.error, urllib.request, typing.Any, typing.Dict, typing.List, typing.Optional
**Execution flow:** Class AutomationNotifier defines method __init__. Class AutomationNotifier defines method is_enabled. Class AutomationNotifier defines method build_payload. Class AutomationNotifier defines method notify.

### File: ./detection_engine/models.py

**Purpose:** detection_engine/models.py
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

    IDS FIELDS (Suricata):
    rule.id            → ids_rule_id
    rule.name          → ids_rule_name
    rule.category      → ids_rule_category
    event.severity     → ids_severity
    ids.severity_label → ids_severity_label
    suricata.alert.action    → ids_alert_action
    suricata.alert.signature → ids_alert_signature
    suricata.alert.category  → ids_alert_category
    suricata.alert.gid       → ids_alert_gid
    suricata.alert.rev       → ids_alert_rev

NO raw log parsing. NO Wazuh field names. NO invented fields.
**Inputs:** parse_timestamp(ts_string); _to_int(value); _to_str(value); _deep_get(d, dotted_key, default); event_from_es_hit(hit)
**Outputs:** parse_timestamp -> datetime; _to_int -> Optional[int]; _to_str -> Optional[str]; event_from_es_hit -> Event
**Dependencies:** __future__.annotations, logging, dataclasses.dataclass, datetime.datetime, datetime.timezone, typing.List, typing.Optional
**Execution flow:** Function parse_timestamp defined. Function _to_int defined. Function _to_str defined. Function _deep_get defined. Function event_from_es_hit defined.

### File: ./detection_engine/alert_template.py

**Purpose:** detection_engine/alert_template.py
Installs the Elasticsearch index template for siem-alerts-* indices.

Ensures all alert fields have explicit mappings so dynamic mapping
never produces type conflicts (e.g. "N/A" in a date field).

Call ensure_template() once at engine startup.
**Inputs:** ensure_template(es)
**Outputs:** ensure_template -> bool
**Dependencies:** __future__.annotations, logging, elasticsearch.Elasticsearch
**Execution flow:** Function ensure_template defined.

### File: ./detection_engine/main.py

**Purpose:** detection_engine/main.py — Entry point for the SIEM-AI Detection Engine v2.0

Wazuh analysisd-style detection for the SIEM-AI project.
Runs a continuous poll loop that:
  1. Installs the siem-alerts index template (once at startup)
  2. Fetches events from ES (siem-raw-*, tagged ready_for_detection)
  3. Maps each hit to an Event using ECS field contract
  4. Passes events through the RuleEngine
  5. Writes fired alerts to ES (siem-alerts-YYYY.MM.dd) after validation
  6. Persists engine state to disk

Usage:
    ES_HOST="http://..." .venv/bin/python -m detection_engine.main

Environment variables:
    ES_HOST        — Elasticsearch host URL  (REQUIRED)
    POLL_INTERVAL  — Seconds between poll cycles  (default: 5)
    LOG_LEVEL      — Python logging level  (default: INFO)
**Inputs:** _log_dropped(hit, reason); _log_unknown(event)
**Outputs:** None
**Dependencies:** __future__.annotations, logging, os, sys, time, elasticsearch.Elasticsearch, .config, alert_template.ensure_template, alert_writer.AlertWriter, elastic_client.ESReader, incident_engine.IncidentEngine, models.event_from_es_hit, rule_engine.RuleEngine, rules.ALL_RULES, state.StateManager, ai_alert_analyzer.AIAlertAnalyzer
**Execution flow:** Function main defined. Function _log_dropped defined. Function _log_unknown defined.

### File: ./detection_engine/ai_alert_analyzer.py

**Purpose:** detection_engine/ai_alert_analyzer.py

Self-contained AI analyzer for individual SIEM alerts.
Does NOT inherit from AIIncidentAnalyzer.
Does NOT import from any other AI module.
Everything lives here.
**Inputs:** AIAlertAnalyzer.__init__(self, es_client, model); AIAlertAnalyzer.is_enabled(self); AIAlertAnalyzer.should_analyze(self, alert_doc, force); AIAlertAnalyzer.analyze_and_update(self, index, doc_id, alert_doc, force); AIAlertAnalyzer.analyze_alert(self, alert_doc, force); AIAlertAnalyzer._build_alert_payload(self, alert_doc); AIAlertAnalyzer._build_prompt(self, payload); AIAlertAnalyzer._call_deepseek(self, messages); AIAlertAnalyzer._validate(self, raw); AIAlertAnalyzer._write_ai_analysis(self, index, doc_id, ai_analysis); AIAlertAnalyzer.analyze_latest_unanalyzed(self, force); AIAlertAnalyzer.analyze_latest_high_or_critical(self, force); AIAlertAnalyzer._fallback_stub(self); AIAlertAnalyzer._clean_string(self, value, default); AIAlertAnalyzer._clean_string_list(self, value); AIAlertAnalyzer._first_present(self); AIAlertAnalyzer._as_dict(self, value); AIAlertAnalyzer._string(self, value); AIAlertAnalyzer._missing(self, value)
**Outputs:** AIAlertAnalyzer.is_enabled -> bool; AIAlertAnalyzer.analyze_and_update -> bool; AIAlertAnalyzer.analyze_alert -> Optional[Dict[str, Any]]; AIAlertAnalyzer._build_alert_payload -> Dict[str, Any]; AIAlertAnalyzer._build_prompt -> List[Dict[str, str]]; AIAlertAnalyzer._call_deepseek -> Dict[str, Any]; AIAlertAnalyzer._validate -> Dict[str, Any]; AIAlertAnalyzer._write_ai_analysis -> bool; AIAlertAnalyzer.analyze_latest_unanalyzed -> bool; AIAlertAnalyzer.analyze_latest_high_or_critical -> bool; AIAlertAnalyzer._fallback_stub -> Dict[str, Any]; AIAlertAnalyzer._clean_string -> str; AIAlertAnalyzer._clean_string_list -> List[str]; AIAlertAnalyzer._first_present -> Any; AIAlertAnalyzer._as_dict -> Dict[str, Any]; AIAlertAnalyzer._string -> str; AIAlertAnalyzer._missing -> bool
**Dependencies:** __future__.annotations, json, logging, operator.index, os, datetime.datetime, datetime.timezone, typing.Any, typing.Dict, typing.List, typing.Optional, elasticsearch.Elasticsearch, openai.OpenAI, lifecycle_contract.ALERT_STATUS_CLOSED
**Execution flow:** Class AIAlertAnalyzer defines method __init__. Class AIAlertAnalyzer defines method is_enabled. Class AIAlertAnalyzer defines method should_analyze. Class AIAlertAnalyzer defines method analyze_and_update. Class AIAlertAnalyzer defines method analyze_alert. Class AIAlertAnalyzer defines method _build_alert_payload. Class AIAlertAnalyzer defines method _build_prompt. Class AIAlertAnalyzer defines method _call_deepseek. Class AIAlertAnalyzer defines method _validate. Class AIAlertAnalyzer defines method _write_ai_analysis. Class AIAlertAnalyzer defines method analyze_latest_unanalyzed. Class AIAlertAnalyzer defines method analyze_latest_high_or_critical. Class AIAlertAnalyzer defines method _fallback_stub. Class AIAlertAnalyzer defines method _clean_string. Class AIAlertAnalyzer defines method _clean_string_list. Class AIAlertAnalyzer defines method _first_present. Class AIAlertAnalyzer defines method _as_dict. Class AIAlertAnalyzer defines method _string. Class AIAlertAnalyzer defines method _missing.

### File: ./detection_engine/__init__.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** None
**Execution flow:** Sequential execution of module level code.

## Folder: ./logs

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./logs/engine.log

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./logs/invalid_alerts.jsonl

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

## Folder: ./scripts

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./scripts/attack_simulator.py

**Purpose:** Python source file.
**Inputs:** banner(text); phase(label); ok(msg); info(msg); expect(msg); warn(msg); _ts_dt(offset_seconds); _ts_spread_dt(start_off, end_off, count, idx); _fmt_syslog(dt); _fmt_nginx(dt); _line_auth_failed(dt, ip, user, port); _line_auth_success(dt, ip, user); _line_sudo_failed(dt, ip, user, seq); _line_sudo_success(dt, user, seq); _nginx_line(dt, ip, method, url, status, size, referrer, user_agent); _pick_ua(seq); _line_web_path_traversal(dt, ip, url, seq); _line_web_sql_injection(dt, ip, url, seq); _line_web_xss(dt, ip, url, seq); _line_web_sensitive_file(dt, ip, url, seq); _line_web_404(dt, ip, url, seq); _build_web_path_traversal_lines(ip, count, start_off, end_off); _build_web_sql_injection_lines(ip, count, start_off, end_off); _build_web_xss_lines(ip, count, start_off, end_off); _build_web_sensitive_file_lines(ip, count, start_off, end_off); _build_web_404_lines(ip, count, start_off, end_off); _build_auth_failed_lines(ip, user, start_off, end_off, count); _build_auth_failed_multi_ip_lines(ip_prefix, ip_start, user, start_off, end_off, count); _build_spray_failure_lines(ip, count, start_off, end_off); _build_auth_success_line(ip, user, offset); _build_sudo_failed_lines(ip, user, start_off, end_off, count); _build_sudo_success_lines(user, count, start_off); _write_phase(lines, label, log_file); _suricata_timestamp(offset_seconds); _suricata_timestamp_pair(offset_seconds, duration_seconds); _network_min_count(scenario, count); _effective_source_ip(override, default); _app_proto_for_port(port, fallback); _suricata_flow_id(src_ip, dest_ip, dest_port, seq, offset_seconds); _append_json_line(path, obj); _write_suricata_flow(path, src_ip, dest_ip, dest_port); _write_suricata_dns(path, src_ip, dns_name); _write_suricata_ids_alert(path); run_network_ids_malware(log_file); run_network_ids_c2(log_file); run_network_ids_exploit(log_file); run_network_ids_scan_recon(log_file); run_network_ids_credential(log_file); run_network_ids_exfiltration(log_file); run_network_ids_policy(log_file); run_network_ids_protocol_anomaly(log_file); run_network_ids_unknown_high(log_file); run_network_ids_c2_with_egress(count, log_file, source_ip); run_network_ids_scan_with_recon(count, log_file, source_ip); run_network_ids_exfil_with_dns(count, log_file, source_ip); run_network_ids_exploit_with_web(count, network_log_file, web_log_file, source_ip); run_network_ids_credential_with_auth(count, network_log_file, auth_log_file, user, source_ip); run_network_port_scan(count, log_file, source_ip); run_network_internal_sweep(count, log_file, source_ip); run_network_suspicious_outbound(count, log_file, source_ip); run_network_c2_beaconing(count, log_file, source_ip); run_network_suspicious_dns(count, log_file, source_ip); run_network_recon_combo(count, log_file, source_ip); run_network_dns_outbound_combo(count, log_file, source_ip); run_network_outbound_beacon_combo(count, log_file, source_ip); run_network_port_scan_repeat(count, log_file, source_ip); run_network_suspicious_outbound_repeat(count, log_file, source_ip); run_web_path_traversal(ip, count, log_file); run_web_sql_injection(ip, count, log_file); run_web_xss(ip, count, log_file); run_web_sensitive_file(ip, count, log_file); run_web_404_scanning(ip, count, log_file); run_ssh_bruteforce(ip, user, count, log_file); run_password_spray(ip, count, log_file); run_user_bruteforce(user, count, log_file); run_distributed_bruteforce(user, count, log_file); run_sudo_bruteforce(ip, user, count, log_file); run_ssh_success_only(ip, user, count, log_file); run_sudo_success_only(ip, user, count, log_file); run_full_attack_chain(ip, user, count, log_file); run_password_spray_chain(ip, count, log_file); run_targeted_account_chain(user, count, log_file); run_distributed_attack_chain(user, count, log_file); run_full_privesc_chain(ip, user, fail_count, sudo_count, log_file); run_targeted_privesc_chain(user, fail_count, sudo_count, log_file); run_distributed_privesc_chain(user, fail_count, sudo_count, log_file); _legacy_ssh_success_after_failures(ip, user, count, log_file); _legacy_scenario_ssh_bruteforce_compromise(ip, user, count, log_file); _legacy_scenario_password_spray_compromise(ip, count, log_file); _legacy_scenario_targeted_account_compromise(user, count, log_file); _legacy_scenario_distributed_account_compromise(user, count, log_file); _legacy_scenario_post_compromise_privesc(ip, user, fail_count, sudo_count, log_file); _legacy_scenario_targeted_3stage(user, fail_count, sudo_count, log_file); _legacy_scenario_distributed_3stage(user, fail_count, sudo_count, log_file)
**Outputs:** utc_now -> datetime; _ts_dt -> datetime; _ts_spread_dt -> datetime; _fmt_syslog -> str; _fmt_nginx -> str; _line_auth_failed -> str; _line_auth_success -> str; _line_sudo_failed -> str; _line_sudo_success -> str; _nginx_line -> str; _pick_ua -> str; _line_web_path_traversal -> str; _line_web_sql_injection -> str; _line_web_xss -> str; _line_web_sensitive_file -> str; _line_web_404 -> str; _build_web_path_traversal_lines -> List[str]; _build_web_sql_injection_lines -> List[str]; _build_web_xss_lines -> List[str]; _build_web_sensitive_file_lines -> List[str]; _build_web_404_lines -> List[str]; _build_auth_failed_lines -> List[str]; _build_auth_failed_multi_ip_lines -> List[str]; _build_spray_failure_lines -> List[str]; _build_auth_success_line -> str; _build_sudo_failed_lines -> List[str]; _build_sudo_success_lines -> List[str]; _suricata_timestamp -> str; _suricata_timestamp_pair -> tuple[str, str]; _network_min_count -> int; _effective_source_ip -> str; _app_proto_for_port -> str; _suricata_flow_id -> int; _write_suricata_flow -> dict; _write_suricata_dns -> dict; _write_suricata_ids_alert -> dict
**Dependencies:** __future__.annotations, argparse, json, os, time, datetime.datetime, datetime.timedelta, datetime.timezone, typing.List
**Execution flow:** Function banner defined. Function phase defined. Function ok defined. Function info defined. Function expect defined. Function warn defined. Function utc_now defined. Function _ts_dt defined. Function _ts_spread_dt defined. Function _fmt_syslog defined. Function _fmt_nginx defined. Function _line_auth_failed defined. Function _line_auth_success defined. Function _line_sudo_failed defined. Function _line_sudo_success defined. Function _nginx_line defined. Function _pick_ua defined. Function _line_web_path_traversal defined. Function _line_web_sql_injection defined. Function _line_web_xss defined. Function _line_web_sensitive_file defined. Function _line_web_404 defined. Function _build_web_path_traversal_lines defined. Function _build_web_sql_injection_lines defined. Function _build_web_xss_lines defined. Function _build_web_sensitive_file_lines defined. Function _build_web_404_lines defined. Function _build_auth_failed_lines defined. Function _build_auth_failed_multi_ip_lines defined. Function _build_spray_failure_lines defined. Function _build_auth_success_line defined. Function _build_sudo_failed_lines defined. Function _build_sudo_success_lines defined. Function _write_phase defined. Function _suricata_timestamp defined. Function _suricata_timestamp_pair defined. Function _network_min_count defined. Function _effective_source_ip defined. Function _app_proto_for_port defined. Function _suricata_flow_id defined. Function _append_json_line defined. Function _write_suricata_flow defined. Function _write_suricata_dns defined. Function _write_suricata_ids_alert defined. Function _ids_summary defined. Function _run_single_ids_scenario defined. Function run_network_ids_malware defined. Function run_network_ids_c2 defined. Function run_network_ids_exploit defined. Function run_network_ids_scan_recon defined. Function run_network_ids_credential defined. Function run_network_ids_exfiltration defined. Function run_network_ids_policy defined. Function run_network_ids_protocol_anomaly defined. Function run_network_ids_unknown_high defined. Function run_network_ids_c2_with_egress defined. Function run_network_ids_scan_with_recon defined. Function run_network_ids_exfil_with_dns defined. Function run_network_ids_exploit_with_web defined. Function run_network_ids_credential_with_auth defined. Function _network_summary defined. Function run_network_port_scan defined. Function run_network_internal_sweep defined. Function run_network_suspicious_outbound defined. Function run_network_c2_beaconing defined. Function run_network_suspicious_dns defined. Function run_network_recon_combo defined. Function run_network_dns_outbound_combo defined. Function run_network_outbound_beacon_combo defined. Function run_network_port_scan_repeat defined. Function run_network_suspicious_outbound_repeat defined. Function run_web_path_traversal defined. Function run_web_sql_injection defined. Function run_web_xss defined. Function run_web_sensitive_file defined. Function run_web_404_scanning defined. Function run_ssh_bruteforce defined. Function run_password_spray defined. Function run_user_bruteforce defined. Function run_distributed_bruteforce defined. Function run_sudo_bruteforce defined. Function run_ssh_success_only defined. Function run_sudo_success_only defined. Function run_full_attack_chain defined. Function run_password_spray_chain defined. Function run_targeted_account_chain defined. Function run_distributed_attack_chain defined. Function run_full_privesc_chain defined. Function run_targeted_privesc_chain defined. Function run_distributed_privesc_chain defined. Function _legacy_ssh_success_after_failures defined. Function _legacy_scenario_ssh_bruteforce_compromise defined. Function _legacy_scenario_password_spray_compromise defined. Function _legacy_scenario_targeted_account_compromise defined. Function _legacy_scenario_distributed_account_compromise defined. Function _legacy_scenario_post_compromise_privesc defined. Function _legacy_scenario_targeted_3stage defined. Function _legacy_scenario_distributed_3stage defined. Function _print_help_scenarios defined. Function main defined.

### File: ./scripts/attack_simulator_updated.py

**Purpose:** Python source file.
**Inputs:** banner(text); phase(label); ok(msg); info(msg); expect(msg); warn(msg); _ts_dt(offset_seconds); _ts_spread_dt(start_off, end_off, count, idx); _fmt_syslog(dt); _fmt_nginx(dt); _line_auth_failed(dt, ip, user, port); _line_auth_success(dt, ip, user); _line_sudo_failed(dt, ip, user, seq); _line_sudo_success(dt, user, seq); _nginx_line(dt, ip, method, url, status, size, referrer, user_agent); _pick_ua(seq); _line_web_path_traversal(dt, ip, url, seq); _line_web_sql_injection(dt, ip, url, seq); _line_web_xss(dt, ip, url, seq); _line_web_sensitive_file(dt, ip, url, seq); _line_web_404(dt, ip, url, seq); _build_web_path_traversal_lines(ip, count, start_off, end_off); _build_web_sql_injection_lines(ip, count, start_off, end_off); _build_web_xss_lines(ip, count, start_off, end_off); _build_web_sensitive_file_lines(ip, count, start_off, end_off); _build_web_404_lines(ip, count, start_off, end_off); _build_auth_failed_lines(ip, user, start_off, end_off, count); _build_auth_failed_multi_ip_lines(ip_prefix, ip_start, user, start_off, end_off, count); _build_spray_failure_lines(ip, count, start_off, end_off); _build_auth_success_line(ip, user, offset); _build_sudo_failed_lines(ip, user, start_off, end_off, count); _build_sudo_success_lines(user, count, start_off); _write_phase(lines, label, log_file); _suricata_timestamp(offset_seconds); _suricata_timestamp_pair(offset_seconds, duration_seconds); _network_min_count(scenario, count); _app_proto_for_port(port, fallback); _suricata_flow_id(src_ip, dest_ip, dest_port, seq, offset_seconds); _append_json_line(path, obj); _write_suricata_flow(path, src_ip, dest_ip, dest_port); _write_suricata_dns(path, src_ip, dns_name); run_network_port_scan(count, log_file); run_network_internal_sweep(count, log_file); run_network_suspicious_outbound(count, log_file); run_network_c2_beaconing(count, log_file); run_network_suspicious_dns(count, log_file); run_network_recon_combo(count, log_file); run_network_dns_outbound_combo(count, log_file); run_network_outbound_beacon_combo(count, log_file); run_network_port_scan_repeat(count, log_file); run_network_suspicious_outbound_repeat(count, log_file); run_web_path_traversal(ip, count, log_file); run_web_sql_injection(ip, count, log_file); run_web_xss(ip, count, log_file); run_web_sensitive_file(ip, count, log_file); run_web_404_scanning(ip, count, log_file); run_ssh_bruteforce(ip, user, count, log_file); run_password_spray(ip, count, log_file); run_user_bruteforce(user, count, log_file); run_distributed_bruteforce(user, count, log_file); run_sudo_bruteforce(ip, user, count, log_file); run_ssh_success_only(ip, user, count, log_file); run_sudo_success_only(ip, user, count, log_file); run_full_attack_chain(ip, user, count, log_file); run_password_spray_chain(ip, count, log_file); run_targeted_account_chain(user, count, log_file); run_distributed_attack_chain(user, count, log_file); run_full_privesc_chain(ip, user, fail_count, sudo_count, log_file); run_targeted_privesc_chain(user, fail_count, sudo_count, log_file); run_distributed_privesc_chain(user, fail_count, sudo_count, log_file); _legacy_ssh_success_after_failures(ip, user, count, log_file); _legacy_scenario_ssh_bruteforce_compromise(ip, user, count, log_file); _legacy_scenario_password_spray_compromise(ip, count, log_file); _legacy_scenario_targeted_account_compromise(user, count, log_file); _legacy_scenario_distributed_account_compromise(user, count, log_file); _legacy_scenario_post_compromise_privesc(ip, user, fail_count, sudo_count, log_file); _legacy_scenario_targeted_3stage(user, fail_count, sudo_count, log_file); _legacy_scenario_distributed_3stage(user, fail_count, sudo_count, log_file)
**Outputs:** utc_now -> datetime; _ts_dt -> datetime; _ts_spread_dt -> datetime; _fmt_syslog -> str; _fmt_nginx -> str; _line_auth_failed -> str; _line_auth_success -> str; _line_sudo_failed -> str; _line_sudo_success -> str; _nginx_line -> str; _pick_ua -> str; _line_web_path_traversal -> str; _line_web_sql_injection -> str; _line_web_xss -> str; _line_web_sensitive_file -> str; _line_web_404 -> str; _build_web_path_traversal_lines -> List[str]; _build_web_sql_injection_lines -> List[str]; _build_web_xss_lines -> List[str]; _build_web_sensitive_file_lines -> List[str]; _build_web_404_lines -> List[str]; _build_auth_failed_lines -> List[str]; _build_auth_failed_multi_ip_lines -> List[str]; _build_spray_failure_lines -> List[str]; _build_auth_success_line -> str; _build_sudo_failed_lines -> List[str]; _build_sudo_success_lines -> List[str]; _suricata_timestamp -> str; _suricata_timestamp_pair -> tuple[str, str]; _network_min_count -> int; _app_proto_for_port -> str; _suricata_flow_id -> int; _write_suricata_flow -> dict; _write_suricata_dns -> dict
**Dependencies:** __future__.annotations, argparse, json, os, time, datetime.datetime, datetime.timedelta, datetime.timezone, typing.List
**Execution flow:** Function banner defined. Function phase defined. Function ok defined. Function info defined. Function expect defined. Function warn defined. Function utc_now defined. Function _ts_dt defined. Function _ts_spread_dt defined. Function _fmt_syslog defined. Function _fmt_nginx defined. Function _line_auth_failed defined. Function _line_auth_success defined. Function _line_sudo_failed defined. Function _line_sudo_success defined. Function _nginx_line defined. Function _pick_ua defined. Function _line_web_path_traversal defined. Function _line_web_sql_injection defined. Function _line_web_xss defined. Function _line_web_sensitive_file defined. Function _line_web_404 defined. Function _build_web_path_traversal_lines defined. Function _build_web_sql_injection_lines defined. Function _build_web_xss_lines defined. Function _build_web_sensitive_file_lines defined. Function _build_web_404_lines defined. Function _build_auth_failed_lines defined. Function _build_auth_failed_multi_ip_lines defined. Function _build_spray_failure_lines defined. Function _build_auth_success_line defined. Function _build_sudo_failed_lines defined. Function _build_sudo_success_lines defined. Function _write_phase defined. Function _suricata_timestamp defined. Function _suricata_timestamp_pair defined. Function _network_min_count defined. Function _app_proto_for_port defined. Function _suricata_flow_id defined. Function _append_json_line defined. Function _write_suricata_flow defined. Function _write_suricata_dns defined. Function _network_summary defined. Function run_network_port_scan defined. Function run_network_internal_sweep defined. Function run_network_suspicious_outbound defined. Function run_network_c2_beaconing defined. Function run_network_suspicious_dns defined. Function run_network_recon_combo defined. Function run_network_dns_outbound_combo defined. Function run_network_outbound_beacon_combo defined. Function run_network_port_scan_repeat defined. Function run_network_suspicious_outbound_repeat defined. Function run_web_path_traversal defined. Function run_web_sql_injection defined. Function run_web_xss defined. Function run_web_sensitive_file defined. Function run_web_404_scanning defined. Function run_ssh_bruteforce defined. Function run_password_spray defined. Function run_user_bruteforce defined. Function run_distributed_bruteforce defined. Function run_sudo_bruteforce defined. Function run_ssh_success_only defined. Function run_sudo_success_only defined. Function run_full_attack_chain defined. Function run_password_spray_chain defined. Function run_targeted_account_chain defined. Function run_distributed_attack_chain defined. Function run_full_privesc_chain defined. Function run_targeted_privesc_chain defined. Function run_distributed_privesc_chain defined. Function _legacy_ssh_success_after_failures defined. Function _legacy_scenario_ssh_bruteforce_compromise defined. Function _legacy_scenario_password_spray_compromise defined. Function _legacy_scenario_targeted_account_compromise defined. Function _legacy_scenario_distributed_account_compromise defined. Function _legacy_scenario_post_compromise_privesc defined. Function _legacy_scenario_targeted_3stage defined. Function _legacy_scenario_distributed_3stage defined. Function _print_help_scenarios defined. Function main defined.

### File: ./scripts/run_detection.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** None
**Execution flow:** Sequential execution of module level code.

## Folder: ./api

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./api/schemas.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** typing.Any, typing.Dict, typing.List, pydantic.BaseModel
**Execution flow:** Sequential execution of module level code.

### File: ./api/setup.py

**Purpose:** api/setup.py

One-time setup wizard endpoint. Creates the admin account and writes
system configuration to Elasticsearch. Refuses to run twice.
**Inputs:** complete_setup(payload, response)
**Outputs:** None
**Dependencies:** bcrypt, logging, datetime.datetime, datetime.timezone, fastapi.APIRouter, fastapi.Response, fastapi.HTTPException, pydantic.BaseModel, typing.Optional, api.elastic.get_es_client, api.auth.create_session_cookie, api.auth._get_admin_user
**Execution flow:** Function complete_setup defined.

### File: ./api/elastic.py

**Purpose:** Python source file.
**Inputs:** es_search(index, query, size); es_count(index, query)
**Outputs:** get_es_client -> Elasticsearch
**Dependencies:** os, logging, elasticsearch.Elasticsearch, elasticsearch.exceptions
**Execution flow:** Function get_es_client defined. Function es_search defined. Function es_count defined.

### File: ./api/auth.py

**Purpose:** api/auth.py

Authentication: login, logout, setup-status check.
Session is a signed cookie (itsdangerous), not a JWT — no external
session store needed, verification is just a signature check.
**Inputs:** create_session_cookie(response, username); verify_session(request); login(payload, response); logout(response); me(request)
**Outputs:** verify_session -> str
**Dependencies:** bcrypt, logging, datetime.datetime, datetime.timezone, fastapi.APIRouter, fastapi.Response, fastapi.Request, fastapi.HTTPException, pydantic.BaseModel, itsdangerous.URLSafeTimedSerializer, itsdangerous.BadSignature, itsdangerous.SignatureExpired, api.elastic.es_search, api.elastic.get_es_client
**Execution flow:** Function _get_admin_user defined. Function create_session_cookie defined. Function verify_session defined. Function auth_status defined. Function login defined. Function logout defined. Function me defined.

### File: ./api/main.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** fastapi.FastAPI, fastapi.middleware.cors.CORSMiddleware, api.schemas.HealthResponse, api.routes.overview.router, api.routes.events.router, api.routes.alerts.router, api.routes.incidents.router, api.routes.sources.router, api.routes.notifications, api.auth, api.setup
**Execution flow:** Function health_check defined.

### File: ./api/__init__.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** None
**Execution flow:** Sequential execution of module level code.

## Folder: ./api/routes

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./api/routes/sources.py

**Purpose:** Python source file.
**Inputs:** get_sources_agg(field_name)
**Outputs:** None
**Dependencies:** fastapi.APIRouter, datetime.datetime, datetime.timezone, api.elastic.get_es_client
**Execution flow:** Function get_sources_agg defined. Function get_sources defined.

### File: ./api/routes/notifications.py

**Purpose:** api/routes/notifications.py

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
**Inputs:** _sev_rank(severity); _fetch_incident_events(es, since_iso, known_state); _fetch_alert_events(es, since_iso, known_state)
**Outputs:** _sev_rank -> int; _fetch_incident_events -> list[dict]; _fetch_alert_events -> list[dict]
**Dependencies:** asyncio, json, logging, datetime.datetime, datetime.timezone, fastapi.APIRouter, fastapi.responses.StreamingResponse, api.elastic.get_es_client, detection_engine.lifecycle_contract.ALERT_STATUS_OPEN, detection_engine.lifecycle_contract.ALERT_STATUS_CLOSED
**Execution flow:** Function _sev_rank defined. Function _fetch_incident_events defined. Function _fetch_alert_events defined. Function notifications_stream defined.

### File: ./api/routes/incidents.py

**Purpose:** Python source file.
**Inputs:** fetch_incident(incident_id); get_incidents(size, status, incident_type, user, host); get_incident_detail(incident_id); get_incident_timeline(incident_id); update_incident_status(incident_id, payload)
**Outputs:** None
**Dependencies:** fastapi.APIRouter, fastapi.Query, fastapi.HTTPException, pydantic.BaseModel, datetime.datetime, datetime.timezone, logging, typing.Optional, api.elastic.es_search, api.elastic.get_es_client, detection_engine.lifecycle_contract.INCIDENT_STATUS_OPEN, detection_engine.lifecycle_contract.INCIDENT_STATUS_CLOSED
**Execution flow:** Function fetch_incident defined. Function get_incidents defined. Function get_incident_detail defined. Function get_incident_timeline defined. Function update_incident_status defined.

### File: ./api/routes/events.py

**Purpose:** Python source file.
**Inputs:** get_events(size, event_action, host, user, source_ip)
**Outputs:** None
**Dependencies:** fastapi.APIRouter, fastapi.Query, typing.Optional, typing.List, api.elastic.es_search
**Execution flow:** Function get_events defined.

### File: ./api/routes/overview.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** fastapi.APIRouter, api.elastic.es_count, api.elastic.es_search, api.schemas.OverviewResponse
**Execution flow:** Function get_overview defined.

### File: ./api/routes/alerts.py

**Purpose:** Python source file.
**Inputs:** fetch_alert(alert_id); get_alerts(size, severity, rule_id, user, source_ip, host); get_alert_detail(alert_id); close_incident(incident_id); update_alert_status(alert_id, payload); _sync_incidents_for_alert(alert_id)
**Outputs:** None
**Dependencies:** fastapi.APIRouter, fastapi.Query, fastapi.HTTPException, pydantic.BaseModel, datetime.datetime, datetime.timezone, typing.Optional, detection_engine.incident_engine.IncidentEngine, api.elastic.es_search, api.elastic.get_es_client, detection_engine.lifecycle_contract.ALERT_STATUS_CLOSED, detection_engine.lifecycle_contract.ALERT_STATUS_OPEN, detection_engine.lifecycle_contract.ALLOWED_ALERT_STATUSES, detection_engine.lifecycle_contract.is_valid_transition, detection_engine.lifecycle_contract.derive_incident_status, detection_engine.lifecycle_contract.INCIDENT_STATUS_OPEN, detection_engine.lifecycle_contract.INCIDENT_STATUS_CLOSED, logging
**Execution flow:** Function fetch_alert defined. Function get_alerts defined. Function get_alert_detail defined. Function close_incident defined. Function update_alert_status defined. Function _sync_incidents_for_alert defined.

### File: ./api/routes/__init__.py

**Purpose:** Python source file.
**Inputs:** None
**Outputs:** None
**Dependencies:** None
**Execution flow:** Sequential execution of module level code.

## Folder: ./frontend2.0

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/siem_ai_refined_v2.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/index.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/siem_ai_mission_control_refined.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/siem_ai_final_editorial.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

## Folder: ./frontend2.0/pages

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/pages/alerts.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/incidents.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/setup-wizard.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/incident.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/alert.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/analytics.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/events.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/investigations.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

### File: ./frontend2.0/pages/login.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

## Folder: ./frontend2.0/assets

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

## Folder: ./frontend2.0/assets/css

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/assets/css/design-system.css

**Purpose:** Cascading Style Sheets for UI styling.
**Inputs:** HTML elements matching selectors.
**Outputs:** Styled DOM.
**Dependencies:** HTML templates.
**Execution flow:** Applied by browser rendering engine.

### File: ./frontend2.0/assets/css/owl-loader.css

**Purpose:** Cascading Style Sheets for UI styling.
**Inputs:** HTML elements matching selectors.
**Outputs:** Styled DOM.
**Dependencies:** HTML templates.
**Execution flow:** Applied by browser rendering engine.

## Folder: ./frontend2.0/assets/js

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/assets/js/owl-loader.js

**Purpose:** Client-side JavaScript logic.
**Inputs:** DOM events, API responses.
**Outputs:** DOM updates, API requests.
**Dependencies:** Other JS modules, HTML DOM.
**Execution flow:** Event-driven or executed on load.

## Folder: ./frontend2.0/assets/fonts

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

## Folder: ./frontend2.0/assets/fonts/technor

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/assets/fonts/technor/Technor-Variable.woff2

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

## Folder: ./frontend2.0/assets/fonts/nippo

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/assets/fonts/nippo/Nippo-Variable.woff2

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

## Folder: ./frontend2.0/assets/fonts/sora

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/assets/fonts/sora/Sora-Variable.woff2

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

## Folder: ./frontend2.0/assets/images

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/assets/images/analytics_owl.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/owl_closed.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/owl_high.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/OWL_Notification_high.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/owl_medium.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/OWL_Notification_critical.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/OWL_Notification_closed.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/owl_low.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/background_owl.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/LOGO_SIEM.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/owl_login.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/OWL_Notification_medium.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/OWL_Notification_low.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

### File: ./frontend2.0/assets/images/owl_critical.png

**Purpose:** Miscellaneous file.
**Inputs:** N/A
**Outputs:** N/A
**Dependencies:** N/A
**Execution flow:** N/A

## Folder: ./frontend2.0/shared

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/shared/components.js

**Purpose:** Client-side JavaScript logic.
**Inputs:** DOM events, API responses.
**Outputs:** DOM updates, API requests.
**Dependencies:** Other JS modules, HTML DOM.
**Execution flow:** Event-driven or executed on load.

### File: ./frontend2.0/shared/utils.js

**Purpose:** Client-side JavaScript logic.
**Inputs:** DOM events, API responses.
**Outputs:** DOM updates, API requests.
**Dependencies:** Other JS modules, HTML DOM.
**Execution flow:** Event-driven or executed on load.

### File: ./frontend2.0/shared/notifications.js

**Purpose:** Client-side JavaScript logic.
**Inputs:** DOM events, API responses.
**Outputs:** DOM updates, API requests.
**Dependencies:** Other JS modules, HTML DOM.
**Execution flow:** Event-driven or executed on load.

### File: ./frontend2.0/shared/api.js

**Purpose:** Client-side JavaScript logic.
**Inputs:** DOM events, API responses.
**Outputs:** DOM updates, API requests.
**Dependencies:** Other JS modules, HTML DOM.
**Execution flow:** Event-driven or executed on load.

### File: ./frontend2.0/shared/state.js

**Purpose:** Client-side JavaScript logic.
**Inputs:** DOM events, API responses.
**Outputs:** DOM updates, API requests.
**Dependencies:** Other JS modules, HTML DOM.
**Execution flow:** Event-driven or executed on load.

## Folder: ./frontend2.0/components

**Purpose:** Container for files in this directory.
**Inputs:** Files and subdirectories.
**Outputs:** Structure of components.
**Dependencies:** Parent directory.
**Execution flow:** N/A (Directory)

### File: ./frontend2.0/components/loader.html

**Purpose:** HTML View template.
**Inputs:** User interactions, frontend routing.
**Outputs:** Rendered DOM elements.
**Dependencies:** Linked CSS/JS files.
**Execution flow:** Rendered by browser upon navigation.

