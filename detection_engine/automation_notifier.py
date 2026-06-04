from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

log = logging.getLogger("detection_engine.automation_notifier")


class AutomationNotifier:
    def __init__(self, webhook_url: Optional[str] = None, timeout_seconds: float = 5.0) -> None:
        self.webhook_url = webhook_url or os.getenv("N8N_WEBHOOK_URL")
        self.timeout_seconds = timeout_seconds
        self.enabled = bool(self.webhook_url)
        if not self.enabled:
            log.warning("N8N_WEBHOOK_URL is not set; n8n notifications are disabled")

    def is_enabled(self) -> bool:
        return self.enabled

    def build_payload(
        self,
        index: str,
        doc_id: str,
        incident_doc: Dict[str, Any],
        ai_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        incident = incident_doc.get("incident", {})
        if not isinstance(incident, dict):
            incident = {}

        attack_context = incident_doc.get("attack_context", {})
        if not isinstance(attack_context, dict):
            attack_context = {}

        def _safe_list(val: Any) -> List[str]:
            if not val:
                return []
            if isinstance(val, str):
                return [val]
            if isinstance(val, list):
                return [str(v) for v in val if v]
            return []

        def _safe_str(val: Any, default: str = "not available") -> str:
            if not val:
                return default
            return str(val)
        
        # Best effort source/dest extractions
        source = incident_doc.get("source", {})
        if not isinstance(source, dict):
            source = {}
        dest = incident_doc.get("destination", {})
        if not isinstance(dest, dict):
            dest = {}
        user = incident_doc.get("user", {})
        if not isinstance(user, dict):
            user = {}
        host = incident_doc.get("host", {})
        if not isinstance(host, dict):
            host = {}

        source_ip = source.get("ip") or attack_context.get("source_ip") or incident_doc.get("source_ip")
        dest_ip = dest.get("ip") or attack_context.get("destination_ip") or incident_doc.get("destination_ip")
        user_name = user.get("name") or attack_context.get("user_name") or incident_doc.get("user_name")
        host_name = host.get("name") or attack_context.get("host_name") or incident_doc.get("host_name")

        # N8N expects these exact fields based on user request
        payload = {
            "event_type": "siem_ai_incidents_notification",
            "index": _safe_str(index, default=""),
            "doc_id": _safe_str(doc_id, default=""),
            "incident_type": _safe_str(incident.get("type") or incident_doc.get("type")),
            "severity": _safe_str(incident.get("severity") or incident_doc.get("severity")),
            "status": _safe_str(incident.get("status") or incident_doc.get("status")),
            "source_ip": _safe_str(source_ip),
            "destination_ip": _safe_str(dest_ip),
            "user": _safe_str(user_name),
            "host": _safe_str(host_name),
            "is_cross_layer": bool(incident.get("is_cross_layer") or incident_doc.get("is_cross_layer")),
            "grouping_key": _safe_str(incident.get("grouping_key") or incident_doc.get("grouping_key")),
            "related_incident_types": _safe_list(attack_context.get("related_incident_types")),
            "layers_seen": _safe_list(attack_context.get("layers_seen")),
            "correlation_reasons": _safe_list(attack_context.get("correlation_reasons")),
            
            # AI fields
            "ai_summary": _safe_str(ai_analysis.get("summary")),
            "ai_attack_story": _safe_str(ai_analysis.get("attack_story")),
            "severity_reasoning": _safe_str(ai_analysis.get("severity_reasoning")),
            "recommended_actions": _safe_list(ai_analysis.get("recommended_actions")),
            "investigation_steps": _safe_list(ai_analysis.get("investigation_steps")),
            "possible_false_positives": _safe_list(ai_analysis.get("possible_false_positives")),
            "soc_ticket_summary": _safe_str(ai_analysis.get("soc_ticket_summary")),
            "ai_provider": _safe_str(ai_analysis.get("provider")),
            "ai_model": _safe_str(ai_analysis.get("model")),
            "ai_generated_at": _safe_str(ai_analysis.get("generated_at")),
        }
        
        return payload

    def notify(
        self,
        index: str,
        doc_id: str,
        incident_doc: Dict[str, Any],
        ai_analysis: Dict[str, Any],
    ) -> bool:
        if not self.enabled:
            return False

        if not ai_analysis:
            return False

        try:
            payload = self.build_payload(index, doc_id, incident_doc, ai_analysis)
            incident_type = payload.get("incident_type", "unknown")
            
            data = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status = response.getcode()
                if status and 200 <= status < 300:
                    log.info("n8n incidents notification sent type=%s doc_id=%s", incident_type, doc_id)
                    return True
                log.warning("n8n incidents notification failed status=%s doc_id=%s", status, doc_id)
                return False
        except Exception as exc:
            log.warning("n8n incidents notification failed safely doc_id=%s: %s", doc_id, exc)
            return False
