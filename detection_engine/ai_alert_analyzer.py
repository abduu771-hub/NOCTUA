"""
detection_engine/ai_alert_analyzer.py

Self-contained AI analyzer for individual SIEM alerts.
Does NOT inherit from AIIncidentAnalyzer.
Does NOT import from any other AI module.
Everything lives here.
"""

from __future__ import annotations

import json
import logging
from operator import index
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from openai import OpenAI
from .lifecycle_contract import ALERT_STATUS_CLOSED
log = logging.getLogger("detection_engine.ai_alert_analyzer")

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

AI_PROVIDER     = "deepseek"
DEFAULT_MODEL   = "deepseek-chat"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"

REQUIRED_AI_KEYS = [
    "executive_brief",
    "execution_key",
    "threat_level",
    "confidence",
    "business_impact",
    "investigation_steps",
    "analyst_notes",
    "generated_at",
    "provider",
    "model",
    "schema_version",
]

VALID_THREAT_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_CONFIDENCE    = {"LOW", "MEDIUM", "HIGH"}

# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are the AI Alert Analyst for SIEM-AI.

The detection engine already detected and classified this alert using deterministic rules.
You are NOT responsible for detection.
You are responsible for explaining one alert in a concise, professional SOC intelligence briefing.

Strict rules:
- Return ONLY valid JSON. No markdown. No code fences. No preamble. No explanation.
- Never invent IP addresses.
- Never invent usernames.
- Never invent hostnames.
- Never invent malware names.
- Never invent domains.
- Never invent commands.
- Never invent file names.
- Never invent timestamps.
- Never invent countries.
- Never invent tools.
- Never invent attacker identities.
- Never invent evidence.
- Use only the alert data provided.
- If information is unavailable, write exactly: not available
- Keep language concise, clinical, and professional.
- Never produce stories or incident narratives.
- Never exaggerate.
- Never claim compromise unless directly supported by the alert evidence.
- Never claim actions have already occurred.
- Only recommend investigation steps.
- Never recommend deleting evidence.
- Never recommend irreversible actions.
- Do not say "it appears that".
- Do not say "it is possible that".
- Do not say "based on the provided information".
- Do not say "likely indicates" unless directly justified by evidence.
- Do not mention AI or that you are an AI.
- Every sentence must have analyst value.
- Use executive SOC language.
- The word json appears here to enable JSON mode.

Required JSON schema — return exactly these keys:
{
    "executive_brief": "",
    "threat_level": "",
    "confidence": "",
    "business_impact": "",
    "investigation_steps": [],
    "analyst_notes": [],
    "generated_at": "",
    "provider": "",
    "model": "",
    "schema_version": 1
}

Field rules:
- executive_brief: Maximum 3 sentences. What happened? Why is it suspicious? What must the analyst know immediately?
- threat_level: One of exactly: LOW, MEDIUM, HIGH, CRITICAL
- confidence: One of exactly: LOW, MEDIUM, HIGH. Confidence in the explanation, not that an attack occurred.
- business_impact: Maximum 2 sentences. Operational impact only. Never invent business context.
- investigation_steps: Maximum 5 items. Short imperative sentences. Example: Review endpoint process tree.
- analyst_notes: Maximum 5 items. Observations only, not recommendations. Example: Repeated outbound communication detected.
- generated_at: Leave as empty string. It will be set by the system.
- provider: Leave as empty string. It will be set by the system.
- model: Leave as empty string. It will be set by the system.
- schema_version: Always 1.
"""

# ══════════════════════════════════════════════════════════════════════════════
# MAIN CLASS
# ══════════════════════════════════════════════════════════════════════════════

class AIAlertAnalyzer:

    def __init__(
        self,
        es_client: Elasticsearch,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self.es      = es_client
        self.model   = model
        self.enabled = False
        self.client: Optional[OpenAI] = None

        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            log.warning(
                "DEEPSEEK_API_KEY is not set — AI alert analysis is disabled"
            )
            return

        self.client  = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
        self.enabled = True

    # ── Public API ────────────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        return self.enabled

    def should_analyze(self, alert_doc, force=False):
        if not self.enabled:
            return False

        # Lifecycle guard — never analyze CLOSED alerts
        # AI is strictly read-only. It never modifies status.
        # It only skips analysis on CLOSED alerts per the lifecycle contract.
        alert_status = self._string(alert_doc.get("status", "")).upper()
        if alert_status == ALERT_STATUS_CLOSED:
            log.info("Skipping AI analysis — alert is CLOSED per lifecycle contract")
            return False

        if force:
            return True

        existing = self._as_dict(alert_doc.get("ai_analysis"))
        if existing.get("execution_key"):
            log.info("Skipping AI analysis — execution_key already present")
            return False
        if not existing.get("generated_at"):
            return True

        # Re-analyze if prior result is a blank stub
        brief = self._string(existing.get("executive_brief", ""))
        is_stub = brief in {"", "not available"}
        if is_stub:
            log.info("Prior ai_analysis is a blank stub — re-analyzing alert")
            return True

        return False

    def analyze_and_update(
        self,
        index: str,
        doc_id: str,
        alert_doc: Dict[str, Any],
        force: bool = False,
    ) -> bool:
        import hashlib
        rule_id   = self._string(self._as_dict(alert_doc.get("rule")).get("id", "unknown"))
        ts_raw    = self._string(alert_doc.get("@timestamp", ""))[:16]  # minute-level bucket
        execution_key = f"{doc_id}:{rule_id}:{ts_raw}"

        ai_analysis = self.analyze_alert(alert_doc=alert_doc, force=force)
        if ai_analysis is None:
            log.warning(
                "AI alert analysis returned None — using fallback stub for doc_id=%s",
                doc_id,
            )
            ai_analysis = self._fallback_stub()
        log.info("AI DEBUG about to write to Elasticsearch")
        log.info("AI DEBUG index=%s", index)
        log.info("AI DEBUG doc_id=%s", doc_id)
        ai_analysis["execution_key"] = execution_key
        written = self._write_ai_analysis(
            index=index,
            doc_id=doc_id,
            ai_analysis=ai_analysis,
        )
        log.info("AI DEBUG write returned=%s", written)

        if written:
            rule_id = self._string(
                self._as_dict(alert_doc.get("rule")).get("id", "unknown")
            )
            log.info(
                "AI alert analysis written for rule=%s doc_id=%s",
                rule_id,
                doc_id,
            )

        return written

    def analyze_alert(
        self,
        alert_doc: Dict[str, Any],
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:
        log.info("AI DEBUG received type=%s", type(alert_doc))
        if not self.enabled:
            log.info("AI alert analysis skipped — analyzer is disabled")
            return None

        try:
            if not self.should_analyze(alert_doc=alert_doc, force=force):
                return None

            payload  = self._build_alert_payload(alert_doc)
            messages = self._build_prompt(payload)
            raw      = self._call_deepseek(messages)
            log.info("AI DEBUG DeepSeek returned")
            validated = self._validate(raw)
            log.info("AI DEBUG validation OK")
            return validated

        except Exception:
            rule_id = self._string(
                self._as_dict(alert_doc.get("rule")).get("id", "unknown")
            )
            log.exception(
                "AI alert analysis failed for rule_id=%s", rule_id
            )
            return None

    # ── Payload builder ───────────────────────────────────────────────────────

    def _build_alert_payload(self, alert_doc: Dict[str, Any]) -> Dict[str, Any]:
        rule           = self._as_dict(alert_doc.get("rule"))
        event          = self._as_dict(alert_doc.get("event"))
        source         = self._as_dict(alert_doc.get("source"))
        destination    = self._as_dict(alert_doc.get("destination"))
        host           = self._as_dict(alert_doc.get("host"))
        user           = self._as_dict(alert_doc.get("user"))
        network        = self._as_dict(alert_doc.get("network"))
        mitre          = self._as_dict(alert_doc.get("mitre"))
        attack_context = self._as_dict(alert_doc.get("attack_context"))
        engine         = self._as_dict(alert_doc.get("engine"))
        evidence       = self._as_dict(alert_doc.get("evidence"))

        # Extract evidence fields — never use raw_events (too verbose for LLM)
        evidence_summary: Dict[str, Any] = {}
        for key, val in evidence.items():
            if key == "raw_events":
                # Summarize count only — never send raw log strings to LLM
                if isinstance(val, list):
                    evidence_summary["raw_event_count"] = len(val)
                continue
            evidence_summary[key] = val

        payload: Dict[str, Any] = {
            # Rule
            "rule_id":          self._first_present(rule.get("id"),          default="not available"),
            "rule_name":        self._first_present(rule.get("name"),        default="not available"),
            "rule_description": self._first_present(rule.get("description"), default="not available"),
            "rule_severity":    self._first_present(rule.get("severity"),    default="not available"),

            # Timing
            "timestamp": self._first_present(
                alert_doc.get("@timestamp"),
                default="not available",
            ),

            # Network
            "source_ip":        self._first_present(source.get("ip"),           default="not available"),
            "source_port":      self._first_present(source.get("port"),         default="not available"),
            "destination_ip":   self._first_present(destination.get("ip"),      default="not available"),
            "destination_port": self._first_present(destination.get("port"),    default="not available"),
            "network_protocol": self._first_present(network.get("protocol"),    default="not available"),
            "network_transport":self._first_present(network.get("transport"),   default="not available"),
            "network_bytes":    self._first_present(network.get("bytes"),       default="not available"),
            "network_packets":  self._first_present(network.get("packets"),     default="not available"),

            # Host / User
            "host_name": self._first_present(host.get("name"), default="not available"),
            "user_name": self._first_present(user.get("name"), default="not available"),

            # Event
            "event_action":   self._first_present(event.get("action"),  default="not available"),
            "event_dataset":  self._first_present(event.get("dataset"), default="not available"),
            "event_count":    self._first_present(event.get("count"),   default="not available"),

            # MITRE
            "mitre_id":        self._first_present(mitre.get("id"),        default="not available"),
            "mitre_tactic":    self._first_present(mitre.get("tactic"),    default="not available"),
            "mitre_technique": self._first_present(mitre.get("technique"), default="not available"),

            # Attack context (deterministic engine output)
            "attack_type":         self._first_present(attack_context.get("attack_type"),         default="not available"),
            "attack_reason":       self._first_present(attack_context.get("reason"),              default="not available"),
            "event_count_window":  self._first_present(attack_context.get("event_count"),         default="not available"),
            "time_window_seconds": self._first_present(attack_context.get("time_window_seconds"), default="not available"),
            "threshold":           self._first_present(attack_context.get("threshold"),           default="not available"),
            "accumulator_type":    self._first_present(attack_context.get("accumulator_type"),    default="not available"),
            "group_key":           self._first_present(attack_context.get("group_key"),           default="not available"),
            "source_ips_seen":     attack_context.get("source_ips_seen", []),
            "destination_ips_seen":attack_context.get("destination_ips_seen", []),
            "hosts_seen":          attack_context.get("hosts_seen", []),
            "first_seen":          self._first_present(attack_context.get("first_seen"), default="not available"),
            "last_seen":           self._first_present(attack_context.get("last_seen"),  default="not available"),

            # Evidence summary (no raw logs)
            "evidence": evidence_summary,

            # Engine
            "engine_version": self._first_present(engine.get("version"), default="not available"),
        }

        return payload

    # ── Prompt builder ────────────────────────────────────────────────────────

    def _build_prompt(self, payload: Dict[str, Any]) -> List[Dict[str, str]]:
        user_prompt = (
            "Analyze this SIEM alert as json.\n\n"
            "Use only the alert data below.\n"
            'If a value is missing, write "not available".\n'
            "Do not invent evidence.\n\n"
            "Alert data:\n"
            f"{json.dumps(payload, indent=2, sort_keys=True, default=str)}\n\n"
            "Return only valid JSON. "
            "The word json appears here to enable JSON mode."
        )

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ]

    # ── DeepSeek call ─────────────────────────────────────────────────────────

    def _call_deepseek(
        self,
        messages: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        if not self.enabled or self.client is None:
            raise RuntimeError("DeepSeek client is unavailable")

        response = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=messages,
            stream=False,
        )
        log.info("STEP 1 response received")

        content = response.choices[0].message.content
        if not content or not content.strip():
            raise ValueError("DeepSeek returned empty content")

        try:
            log.info("STEP 2 content extracted")

            parsed = json.loads(content)
        except json.JSONDecodeError:
            log.exception("DeepSeek returned invalid JSON for alert analysis")
            raise
        log.info("STEP 3 json parsed")


        if not isinstance(parsed, dict):
            raise ValueError("DeepSeek alert response must be a JSON object")
        log.info("STEP 4 returning parsed dict")


        return parsed

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        cleaned: Dict[str, Any] = {}

        # Strings
        for key in ("executive_brief", "business_impact"):
            cleaned[key] = self._clean_string(raw.get(key), default="not available")

        # Threat level
        threat = self._string(raw.get("threat_level", "")).upper()
        cleaned["threat_level"] = threat if threat in VALID_THREAT_LEVELS else "MEDIUM"

        # Confidence
        conf = self._string(raw.get("confidence", "")).upper()
        cleaned["confidence"] = conf if conf in VALID_CONFIDENCE else "MEDIUM"

        # Lists
        for key in ("investigation_steps", "analyst_notes"):
            cleaned[key] = self._clean_string_list(raw.get(key))

        # System-set fields — always overwrite whatever LLM returned
        cleaned["generated_at"]   = datetime.now(timezone.utc).isoformat()
        cleaned["provider"]       = AI_PROVIDER
        cleaned["model"]          = self.model
        cleaned["schema_version"] = 1

        return cleaned

    # ── Elasticsearch write ───────────────────────────────────────────────────

    def _write_ai_analysis(
        self,
        index: str,
        doc_id: str,
        ai_analysis: Dict[str, Any],
    ) -> bool:
        try:
            log.info("AI DEBUG executing ES update")
            self.es.update(
                index=index,
                id=doc_id,
                body={"doc": {"ai_analysis": ai_analysis}},
                refresh="wait_for",
            )
            log.info("AI DEBUG ES update SUCCESS")
            return True
        except Exception:
            log.exception(
                "Failed to write AI alert analysis for doc_id=%s index=%s",
                doc_id,
                index,
            )
            return False

    # ── Auto-analyze (latest unanalyzed alert) ────────────────────────────────

    def analyze_latest_unanalyzed(self, force: bool = False) -> bool:
        query: Dict[str, Any] = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "_source": True,
            "query": {
                "bool": {
                    "must_not": [
                        {"exists": {"field": "ai_analysis.generated_at"}}
                    ]
                }
            },
        }

        if force:
            query.pop("query", None)

        try:
            response = self.es.search(index="siem-alerts-*", body=query)
            hits = response.get("hits", {}).get("hits", [])

            if not hits:
                log.info("No unanalyzed alert found")
                return False

            hit       = hits[0]
            index     = hit.get("_index")
            doc_id    = hit.get("_id")
            alert_doc = hit.get("_source")

            if not index or not doc_id or not isinstance(alert_doc, dict):
                log.warning("Invalid Elasticsearch hit for AI alert analysis")
                return False

            return self.analyze_and_update(
                index=index,
                doc_id=doc_id,
                alert_doc=alert_doc,
                force=force,
            )

        except Exception:
            log.exception("Failed to fetch latest unanalyzed alert")
            return False

    def analyze_latest_high_or_critical(self, force: bool = False) -> bool:
        query: Dict[str, Any] = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "_source": True,
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"rule.severity": ["HIGH", "CRITICAL"]}}
                    ]
                }
            },
        }

        if not force:
            query["query"]["bool"]["must_not"] = [
                {"exists": {"field": "ai_analysis.generated_at"}}
            ]

        try:
            response = self.es.search(index="siem-alerts-*", body=query)
            hits = response.get("hits", {}).get("hits", [])

            if not hits:
                log.info("No HIGH/CRITICAL unanalyzed alert found")
                return False

            hit       = hits[0]
            index     = hit.get("_index")
            doc_id    = hit.get("_id")
            alert_doc = hit.get("_source")

            if not index or not doc_id or not isinstance(alert_doc, dict):
                log.warning("Invalid Elasticsearch hit for AI alert analysis")
                return False

            return self.analyze_and_update(
                index=index,
                doc_id=doc_id,
                alert_doc=alert_doc,
                force=force,
            )

        except Exception:
            log.exception("Failed to analyze latest HIGH/CRITICAL alert")
            return False

    # ── Fallback stub ─────────────────────────────────────────────────────────

    def _fallback_stub(self) -> Dict[str, Any]:
        return {
            "executive_brief":    "not available",
            "threat_level":       "MEDIUM",
            "confidence":         "MEDIUM",
            "business_impact":    "not available",
            "investigation_steps": [],
            "analyst_notes":      [],
            "generated_at":       datetime.now(timezone.utc).isoformat(),
            "provider":           AI_PROVIDER,
            "model":              self.model,
            "schema_version":     1,
            "execution_key":      "",
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _clean_string(self, value: Any, default: str = "not available") -> str:
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            text = json.dumps(value, sort_keys=True, default=str)
        else:
            text = str(value)
        text = text.strip()
        return text if text else default

    def _clean_string_list(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, list):
            items = value
        else:
            items = [value]
        cleaned: List[str] = []
        seen: set = set()
        for item in items:
            text = self._clean_string(item, default="")
            if text and text not in seen:
                seen.add(text)
                cleaned.append(text)
        return cleaned

    def _first_present(self, *values: Any, default: Any = None) -> Any:
        for value in values:
            if not self._missing(value):
                return value
        return default

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _string(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, default=str).strip()
        return str(value).strip()

    def _missing(self, value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            text = value.strip()
            return not text or text.lower() in {"none", "null", "n/a", "not available"}
        if isinstance(value, (list, dict)):
            return len(value) == 0
        return False


# ══════════════════════════════════════════════════════════════════════════════
# MANUAL RUN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(
        level=_logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    _es = Elasticsearch("http://localhost:9200")
    _analyzer = AIAlertAnalyzer(_es)

    if _analyzer.analyze_latest_high_or_critical(force=False):
        print("AI alert analysis completed")
    else:
        print("No alert analyzed")