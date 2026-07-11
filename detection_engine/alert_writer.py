"""
detection_engine/alert_writer.py
Writes alert documents to Elasticsearch.

Responsibilities:
  - Receive already-built alert documents
  - Validate via alert_validator before indexing
  - Write valid alerts to siem-alerts-YYYY.MM.dd
  - Buffer failed ES writes to logs/alerts_buffer.jsonl

MUST NOT create alert content — that is alert_builder's job.
MUST NOT evaluate rules.
MUST NOT insert "N/A" values.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from elasticsearch import Elasticsearch

from . import config
from .alert_validator import validate_alert
from .lifecycle_contract import ALERT_STATUS_OPEN

log = logging.getLogger("detection_engine.alert_writer")


class AlertWriter:
    """
    Validates and writes alert documents to Elasticsearch.
    Falls back to local JSONL buffer on ES write failure.
    """

    def __init__(
        self,
        es_client: Elasticsearch,
        index_prefix: str = config.ES_ALERTS_INDEX_PREFIX,
        buffer_path: str = config.ALERTS_BUFFER_FILE,
    ):
        self.es = es_client
        self._index_prefix = index_prefix
        self._buffer_path = buffer_path
        os.makedirs(os.path.dirname(buffer_path) or ".", exist_ok=True)

    def _index_name(self) -> str:
        """Date-based alert index: siem-alerts-YYYY.MM.dd"""
        date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self._index_prefix}-{date_str}"

    def write(self, alert: dict) -> Optional[str]:
        # 1. Deep copy — prevent any nested mutation of caller's object
        alert = copy.deepcopy(alert)

        # 2. Lifecycle field enforcement — alert_writer is the ONLY creator.
        # Status is always OPEN at creation. Only the admin API can change it later.
        # If status is missing or wrong, we correct it here before validation.
        now_iso = datetime.now(timezone.utc).isoformat()

        if alert.get("status") != ALERT_STATUS_OPEN:
            alert["status"] = ALERT_STATUS_OPEN

        if not alert.get("opened_at"):
            alert["opened_at"] = now_iso

        if not alert.get("last_status_change"):
            alert["last_status_change"] = now_iso

        # Ensure closed fields are null on creation — they are admin-only
        alert["closed_at"] = None
        alert["closed_by"] = None
        alert["reopened_at"] = None
        alert["reopened_by"] = None

        # 3. Schema validation via alert_validator
        is_valid, error = validate_alert(alert)
        if not is_valid:
            log.warning(
                "Alert rejected by validator: %s (rule=%s)",
                error,
                alert.get("rule", {}).get("id", "unknown"),
            )
            return None

        # 4. Write to Elasticsearch
        try:
            result = self.es.index(
                index=self._index_name(),
                body=alert,
                refresh="wait_for",
            )
            log.info(
                "Alert indexed: [%s] %s",
                alert.get("rule", {}).get("severity", "?"),
                alert.get("rule", {}).get("id", "?"),
            )
            # 5. Return ES _id on success
            return result["_id"]
        except Exception as exc:
            log.error("ES alert write failed: %s — buffering to disk", exc)
            self._buffer_to_disk(alert)
            return None

    def flush_buffer(self) -> None:
        """
        Re-send buffered alerts from previous failures.
        Called at the start of every poll cycle.
        """
        if not os.path.exists(self._buffer_path):
            return
        try:
            size = os.path.getsize(self._buffer_path)
        except OSError:
            return
        if size == 0:
            return

        try:
            with open(self._buffer_path, "r") as f:
                lines = f.readlines()

            resent = 0
            for line in lines:
                try:
                    alert = json.loads(line.strip())
                    self.es.index(
                        index=self._index_name(),
                        body=alert,
                        refresh="wait_for",
                    )
                    resent += 1
                except Exception as exc:
                    log.error("Buffer flush failed for alert: %s", exc)
                    continue

            if resent == len(lines):
                open(self._buffer_path, "w").close()
                log.info("Flushed %d buffered alerts to ES", resent)
            elif resent > 0:
                with open(self._buffer_path, "w") as f:
                    f.writelines(lines[resent:])
                log.info(
                    "Partially flushed %d/%d buffered alerts",
                    resent,
                    len(lines),
                )
        except Exception as exc:
            log.error("Buffer flush error: %s", exc)

    def _buffer_to_disk(self, alert: dict) -> None:
        try:
            with open(self._buffer_path, "a") as f:
                f.write(json.dumps(alert, default=str) + "\n")
                f.flush()
            log.info("Alert buffered to %s", self._buffer_path)
        except Exception:
            pass