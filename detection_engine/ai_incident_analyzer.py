from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from openai import OpenAI

try:
    from detection_engine.automation_notifier import AutomationNotifier
except ImportError:
    AutomationNotifier = None

log = logging.getLogger("detection_engine.ai_incident_analyzer")

AI_PROVIDER = "deepseek"
DEFAULT_MODEL = "deepseek-chat"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"

REQUIRED_AI_KEYS = [
    "summary",
    "attack_story",
    "severity_reasoning",
    "confidence",
    "evidence",
    "recommended_actions",
    "investigation_steps",
    "possible_false_positives",
    "soc_ticket_summary",
]

LIST_FIELDS = [
    "evidence",
    "recommended_actions",
    "investigation_steps",
    "possible_false_positives",
]

VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}

IMPORTANT_INCIDENT_TYPES = {
    "account_compromise",
    "possible command and control",
    "ids / command and control",
    "ids / malware network activity",
    "account compromise with malware activity",
    "host compromise with c2",
    "full kill chain intrusion",
    "web server compromise",
    "confirmed web exploitation",
    "malware c2 chain",
    "internal lateral movement",
    "multi-layer intrusion attempt",
}

SYSTEM_PROMPT = """You are the AI Incident Analyst for ABUR - SIEM, a custom SIEM detection and incident correlation engine.

ABUR - SIEM already detects attacks using deterministic rules.
You are NOT responsible for detecting new attacks.
You are responsible for explaining the incident, summarizing evidence, reasoning about severity, and recommending safe response actions.

Strict rules:
- Return ONLY valid JSON.
- Do not use markdown.
- Do not wrap the JSON in code fences.
- Do not invent facts.
- Do not invent IP addresses, users, hosts, malware names, domains, commands, file names, timestamps, countries, tools, or attacker identities.
- Use only the incident data provided.
- If information is missing, write "not available".
- Do not say something is confirmed unless the incident evidence directly supports it.
- Do not claim containment actions were executed.
- Recommend actions only.
- Do not recommend deleting evidence.
- Recommend preserving logs and evidence when relevant.
- Keep the language professional, clear, and useful for a SOC analyst.
- The word json appears here to enable JSON mode.

Required JSON keys:
summary,
attack_story,
severity_reasoning,
confidence,
evidence,
recommended_actions,
investigation_steps,
possible_false_positives,
soc_ticket_summary.

Field requirements:
- confidence must be one of: LOW, MEDIUM, HIGH.
- evidence must be a list of strings using only provided evidence.
- recommended_actions must be a list of safe response actions.
- investigation_steps must be a list of checks the analyst should perform.
- possible_false_positives must be a list of possible benign explanations.
- soc_ticket_summary must be short and ticket-ready.
"""


class AIIncidentAnalyzer:
    def __init__(self, es_client: Elasticsearch, model: str = DEFAULT_MODEL) -> None:
        self.es = es_client
        self.model = model
        self.enabled = False
        self.client: Optional[OpenAI] = None
        self.notifier = AutomationNotifier() if AutomationNotifier else None

        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            log.warning("DEEPSEEK_API_KEY is not set; AI incident analysis is disabled")
            return

        self.client = OpenAI(
            api_key=api_key,
            base_url=DEEPSEEK_BASE_URL,
        )
        self.enabled = True

    def is_enabled(self) -> bool:
        return self.enabled

    def should_analyze(self, incident_doc: Dict[str, Any], force: bool = False) -> bool:
        if force:
            return True

        if not self.enabled:
            return False

        incident = self._as_dict(incident_doc.get("incident"))
        ai_analysis = self._as_dict(incident_doc.get("ai_analysis"))

        status = self._string(
            incident.get("status")
            or incident_doc.get("status")
        ).lower()

        if status == "closed":
            return False

        if ai_analysis.get("generated_at"):
            return False

        severity = self._string(
            incident.get("severity")
            or incident_doc.get("severity")
        ).upper()

        if severity in {"HIGH", "CRITICAL"}:
            return True

        if self._bool(
            incident.get("is_cross_layer")
            or incident_doc.get("is_cross_layer")
        ):
            return True

        incident_type = self._string(
            incident.get("type")
            or incident_doc.get("type")
        ).lower()

        if not incident_type:
            return False

        return any(
            important_type in incident_type
            for important_type in IMPORTANT_INCIDENT_TYPES
        )

    def build_incident_payload(self, incident_doc: Dict[str, Any]) -> Dict[str, Any]:
        incident = self._as_dict(incident_doc.get("incident"))
        source = self._as_dict(incident_doc.get("source"))
        destination = self._as_dict(incident_doc.get("destination"))
        user = self._as_dict(incident_doc.get("user"))
        host = self._as_dict(incident_doc.get("host"))
        attack_context = self._as_dict(incident_doc.get("attack_context"))
        related = self._as_dict(incident_doc.get("related"))

        payload: Dict[str, Any] = {
            "incident_type": self._first_present(
                incident.get("type"),
                incident_doc.get("type"),
                default="not available",
            ),
            "severity": self._first_present(
                incident.get("severity"),
                incident_doc.get("severity"),
                default="not available",
            ),
            "status": self._first_present(
                incident.get("status"),
                incident_doc.get("status"),
                default="not available",
            ),
            "grouping_key": self._first_present(
                incident.get("grouping_key"),
                incident_doc.get("grouping_key"),
                default="not available",
            ),
            "is_cross_layer": self._bool(
                incident.get("is_cross_layer")
                or incident_doc.get("is_cross_layer")
            ),
            "source_ip": self._limited_value(
                self._first_present(
                    source.get("ip"),
                    incident_doc.get("source_ip"),
                    default=None,
                ),
                max_items=20,
            ) or "not available",
            "source_port": self._first_present(
                source.get("port"),
                incident_doc.get("source_port"),
                default="not available",
            ),
            "destination_ip": self._limited_value(
                self._first_present(
                    destination.get("ip"),
                    incident_doc.get("destination_ip"),
                    default=None,
                ),
                max_items=20,
            ) or "not available",
            "destination_port": self._first_present(
                destination.get("port"),
                incident_doc.get("destination_port"),
                default="not available",
            ),
            "user": self._limited_value(
                self._first_present(
                    user.get("name"),
                    incident_doc.get("user_name"),
                    default=None,
                ),
                max_items=20,
            ) or "not available",
            "host": self._limited_value(
                self._first_present(
                    host.get("name"),
                    incident_doc.get("host_name"),
                    default=None,
                ),
                max_items=20,
            ) or "not available",
            "created_at": self._first_present(
                incident_doc.get("created_at"),
                incident.get("created_at"),
                default="not available",
            ),
            "updated_at": self._first_present(
                incident_doc.get("updated_at"),
                incident.get("updated_at"),
                default="not available",
            ),
            "first_seen": self._first_present(
                incident.get("first_seen"),
                incident_doc.get("first_seen"),
                default="not available",
            ),
            "last_seen": self._first_present(
                incident.get("last_seen"),
                incident_doc.get("last_seen"),
                default="not available",
            ),
            "alert_count": self._first_present(
                incident.get("alert_count"),
                incident_doc.get("alert_count"),
                default="not available",
            ),
            "incident_count": self._first_present(
                incident.get("incident_count"),
                incident_doc.get("incident_count"),
                default="not available",
            ),
            "attack_context": self._compact_dict(attack_context),
            "related_incident_ids": self._extract_related_values(
                related,
                keys=("incident_ids", "incident_id", "incidents", "ids"),
                max_items=20,
            ),
            "related_incident_types": self._extract_related_values(
                related,
                keys=("incident_types", "incident_type", "types"),
                max_items=20,
            ),
            "related_rule_ids": self._extract_related_values(
                related,
                keys=("rule_ids", "rule_id", "rules"),
                max_items=20,
            ),
            "related_alert_ids": self._extract_related_values(
                related,
                keys=("alert_ids", "alert_id", "alerts"),
                max_items=30,
            ),
        }

        payload["evidence"] = self._build_evidence(payload=payload)[:25]
        return payload

    def build_prompt(self, payload: Dict[str, Any]) -> List[Dict[str, str]]:
        user_prompt = (
            "Analyze this SIEM incident as json.\n\n"
            "Use only the incident data below.\n"
            'If a value is missing, write "not available".\n'
            "Do not invent evidence.\n\n"
            "Incident data:\n"
            f"{json.dumps(payload, indent=2, sort_keys=True, default=str)}\n\n"
            "Make sure the word json is present in the user prompt too."
        )

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def call_deepseek(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        if not self.enabled or self.client is None:
            raise RuntimeError("DeepSeek client is unavailable")

        response = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=messages,
            stream=False,
        )

        content = response.choices[0].message.content
        if not content or not content.strip():
            raise ValueError("DeepSeek returned empty content")

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            log.exception("DeepSeek returned invalid JSON")
            raise

        if not isinstance(parsed, dict):
            raise ValueError("DeepSeek response JSON must be an object")

        return parsed

    def validate_ai_analysis(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        cleaned: Dict[str, Any] = {}

        for key in REQUIRED_AI_KEYS:
            value = analysis.get(key)

            if key in LIST_FIELDS:
                cleaned[key] = self._clean_string_list(value)
                continue

            if key == "confidence":
                confidence = self._string(value).upper()
                cleaned[key] = confidence if confidence in VALID_CONFIDENCE else "MEDIUM"
                continue

            cleaned[key] = self._clean_string(value, default="not available")

        cleaned["provider"] = AI_PROVIDER
        cleaned["model"] = self.model
        cleaned["generated_at"] = datetime.now(timezone.utc).isoformat()
        cleaned["schema_version"] = 1

        return cleaned

    def analyze_incident(
        self,
        incident_doc: Dict[str, Any],
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            log.info("AI incident analysis skipped because analyzer is disabled")
            return None

        try:
            if not self.should_analyze(incident_doc=incident_doc, force=force):
                return None

            payload = self.build_incident_payload(incident_doc)
            messages = self.build_prompt(payload)
            raw_analysis = self.call_deepseek(messages)
            return self.validate_ai_analysis(raw_analysis)

        except Exception:
            incident = self._as_dict(incident_doc.get("incident"))
            incident_type = self._first_present(
                incident.get("type"),
                incident_doc.get("type"),
                default="unknown",
            )
            log.exception("AI incident analysis failed for incident type=%s", incident_type)
            return None

    def write_ai_analysis(
        self,
        index: str,
        doc_id: str,
        ai_analysis: Dict[str, Any],
    ) -> bool:
        try:
            self.es.update(
                index=index,
                id=doc_id,
                body={"doc": {"ai_analysis": ai_analysis}},
                refresh="wait_for",
            )
            return True
        except Exception:
            log.exception("Failed to write AI analysis for doc_id=%s index=%s", doc_id, index)
            return False

    def analyze_and_update(
        self,
        index: str,
        doc_id: str,
        incident_doc: Dict[str, Any],
        force: bool = False,
    ) -> bool:
        ai_analysis = self.analyze_incident(
            incident_doc=incident_doc,
            force=force,
        )

        if ai_analysis is None:
            return False

        written = self.write_ai_analysis(
            index=index,
            doc_id=doc_id,
            ai_analysis=ai_analysis,
        )

        if written:
            incident = self._as_dict(incident_doc.get("incident"))
            incident_type = self._first_present(
                incident.get("type"),
                incident_doc.get("type"),
                default="unknown",
            )
            log.info("AI analysis written for incident type=%s doc_id=%s", incident_type, doc_id)

            if self.notifier:
                try:
                    self.notifier.notify(index, doc_id, incident_doc, ai_analysis)
                except Exception as exc:
                    log.warning("n8n incidents notification failed safely: %s", exc)

        return written

    def analyze_latest_high_or_critical(self, force: bool = False) -> bool:
        query: Dict[str, Any] = {
            "size": 1,
            "sort": [
                {"updated_at": {"order": "desc", "unmapped_type": "date"}},
                {"created_at": {"order": "desc", "unmapped_type": "date"}},
            ],
            "_source": [
                "incident",
                "source",
                "destination",
                "user",
                "host",
                "attack_context",
                "related",
                "created_at",
                "updated_at",
                "ai_analysis",
            ],
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"incident.severity.keyword": ["HIGH", "CRITICAL"]}}
                    ]
                }
            },
        }

        if not force:
            query["query"]["bool"]["must_not"] = [
                {"exists": {"field": "ai_analysis.generated_at"}}
            ]

        try:
            response = self.es.search(
                index="siem-incidents-*",
                body=query,
            )

            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                log.info("No HIGH/CRITICAL incident found for AI analysis")
                return False

            hit = hits[0]
            index = hit.get("_index")
            doc_id = hit.get("_id")
            incident_doc = hit.get("_source")

            if not index or not doc_id or not isinstance(incident_doc, dict):
                log.warning("Invalid Elasticsearch hit returned for AI analysis")
                return False

            return self.analyze_and_update(
                index=index,
                doc_id=doc_id,
                incident_doc=incident_doc,
                force=force,
            )

        except Exception:
            log.exception("Failed to analyze latest HIGH/CRITICAL incident")
            return False

    def _build_evidence(self, payload: Dict[str, Any]) -> List[str]:
        evidence: List[str] = []

        self._add_evidence(evidence, "Incident type", payload.get("incident_type"))
        self._add_evidence(evidence, "Severity", payload.get("severity"))
        self._add_evidence(evidence, "Status", payload.get("status"))
        self._add_evidence(evidence, "Grouping key", payload.get("grouping_key"))
        self._add_evidence(evidence, "Source IP", payload.get("source_ip"))
        self._add_evidence(evidence, "Source port", payload.get("source_port"))
        self._add_evidence(evidence, "Destination IP", payload.get("destination_ip"))
        self._add_evidence(evidence, "Destination port", payload.get("destination_port"))
        self._add_evidence(evidence, "User", payload.get("user"))
        self._add_evidence(evidence, "Host", payload.get("host"))
        self._add_evidence(evidence, "Created at", payload.get("created_at"))
        self._add_evidence(evidence, "Updated at", payload.get("updated_at"))
        self._add_evidence(evidence, "First seen", payload.get("first_seen"))
        self._add_evidence(evidence, "Last seen", payload.get("last_seen"))
        self._add_evidence(evidence, "Related incidents", payload.get("related_incident_ids"))
        self._add_evidence(evidence, "Related incident types", payload.get("related_incident_types"))
        self._add_evidence(evidence, "Related rules", payload.get("related_rule_ids"))
        self._add_evidence(evidence, "Related alerts", payload.get("related_alert_ids"))

        if payload.get("is_cross_layer"):
            evidence.append("Incident is marked as cross-layer correlation")

        attack_context = self._as_dict(payload.get("attack_context"))
        for key in (
            "correlation_reason",
            "correlation_reasons",
            "layers_seen",
            "layer",
            "rule_id",
            "rule_ids",
            "signature_id",
            "signature",
            "signature_name",
            "signature_category",
            "ids_category",
            "category",
            "attack_summary",
            "summary",
        ):
            value = attack_context.get(key)
            self._add_evidence(evidence, self._humanize_key(key), value)

        return self._dedupe(evidence)

    def _add_evidence(self, evidence: List[str], label: str, value: Any) -> None:
        if self._missing(value):
            return

        if isinstance(value, list):
            items = [self._string(item) for item in value if not self._missing(item)]
            items = [item for item in items if item]
            if items:
                evidence.append(f"{label}: {', '.join(items[:20])}")
            return

        if isinstance(value, dict):
            compact = self._compact_dict(value)
            if compact:
                evidence.append(f"{label}: {json.dumps(compact, sort_keys=True, default=str)}")
            return

        text = self._string(value)
        if text:
            evidence.append(f"{label}: {text}")

    def _extract_related_values(
        self,
        related: Dict[str, Any],
        keys: tuple[str, ...],
        max_items: int,
    ) -> List[str]:
        values: List[str] = []

        for key in keys:
            values.extend(self._flatten_to_strings(related.get(key)))

        return self._dedupe(values)[:max_items]

    def _flatten_to_strings(self, value: Any) -> List[str]:
        if self._missing(value):
            return []

        if isinstance(value, list):
            values: List[str] = []
            for item in value:
                values.extend(self._flatten_to_strings(item))
            return values

        if isinstance(value, tuple) or isinstance(value, set):
            values = []
            for item in value:
                values.extend(self._flatten_to_strings(item))
            return values

        if isinstance(value, dict):
            values = []
            for key in ("id", "_id", "incident_id", "alert_id", "rule_id", "type", "name"):
                if key in value:
                    values.extend(self._flatten_to_strings(value.get(key)))

            if values:
                return values

            compact = self._compact_dict(value, max_keys=10, max_list_items=5)
            if compact:
                return [json.dumps(compact, sort_keys=True, default=str)]

            return []

        text = self._string(value)
        return [text] if text else []

    def _compact_dict(
        self,
        value: Dict[str, Any],
        max_keys: int = 40,
        max_list_items: int = 20,
    ) -> Dict[str, Any]:
        if not isinstance(value, dict):
            return {}

        compact: Dict[str, Any] = {}

        for index, (key, raw_value) in enumerate(value.items()):
            if index >= max_keys:
                break

            if self._missing(raw_value):
                continue

            key_text = str(key)

            if isinstance(raw_value, dict):
                nested = self._compact_dict(
                    raw_value,
                    max_keys=20,
                    max_list_items=10,
                )
                if nested:
                    compact[key_text] = nested
                continue

            if isinstance(raw_value, list):
                cleaned_items = []

                for item in raw_value[:max_list_items]:
                    if self._missing(item):
                        continue

                    if isinstance(item, dict):
                        nested_item = self._compact_dict(
                            item,
                            max_keys=10,
                            max_list_items=5,
                        )
                        if nested_item:
                            cleaned_items.append(nested_item)
                    else:
                        cleaned_items.append(item)

                if cleaned_items:
                    compact[key_text] = cleaned_items

                continue

            compact[key_text] = raw_value

        return compact

    def _clean_string_list(self, value: Any) -> List[str]:
        if value is None:
            return []

        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            values = [value]

        cleaned = []

        for item in values:
            text = self._clean_string(item, default="")
            if text:
                cleaned.append(text)

        return self._dedupe(cleaned)

    def _clean_string(self, value: Any, default: str = "not available") -> str:
        if value is None:
            return default

        if isinstance(value, (dict, list)):
            text = json.dumps(value, sort_keys=True, default=str)
        else:
            text = str(value)

        text = text.strip()
        return text if text else default

    def _first_present(self, *values: Any, default: Any = None) -> Any:
        for value in values:
            if not self._missing(value):
                return value
        return default

    def _limited_value(self, value: Any, max_items: int) -> Any:
        if isinstance(value, list):
            return [item for item in value if not self._missing(item)][:max_items]
        return value

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _string(self, value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, default=str).strip()

        return str(value).strip()

    def _bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "y"}

        return bool(value)

    def _missing(self, value: Any) -> bool:
        if value is None:
            return True

        if isinstance(value, str):
            text = value.strip()
            return not text or text.lower() in {"none", "null", "n/a", "not available"}

        if isinstance(value, list):
            return len(value) == 0

        if isinstance(value, dict):
            return len(value) == 0

        return False

    def _dedupe(self, values: List[str]) -> List[str]:
        seen = set()
        output = []

        for value in values:
            text = self._string(value)
            if not text or text in seen:
                continue

            seen.add(text)
            output.append(text)

        return output

    def _humanize_key(self, key: str) -> str:
        return key.replace("_", " ").strip().title()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    es = Elasticsearch("http://localhost:9200")
    analyzer = AIIncidentAnalyzer(es)

    if analyzer.analyze_latest_high_or_critical(force=False):
        print("AI analysis completed")
    else:
        print("No incident analyzed")


# UPDATES DONE:
# 1. Query simplified inside analyze_latest_high_or_critical().
# 2. Status filter removed for manual testing.
# 3. Severity filter now uses incident.severity.keyword terms with ["HIGH", "CRITICAL"].
# 4. _source filtering added to reduce Elasticsearch response size.
# 5. DeepSeek logic unchanged.
# 6. Prompts unchanged.
# 7. Validation unchanged.
# 8. write_ai_analysis unchanged.
# 9. Compile command to run:
#    python3 -m py_compile /home/abdu/SIEM-AI/detection_engine/ai_incident_analyzer.py
# 10. Manual test command to run:
#     cd /home/abdu/SIEM-AI
#     source .venv/bin/activate
#     python3 -m detection_engine.ai_incident_analyzer