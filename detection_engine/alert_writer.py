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

import json
import logging
import os
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

from . import config
from .alert_validator import validate_alert

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

    def write(self, alert: dict) -> bool:
        """
        Validate and write one alert to ES.

        Returns True on successful ES write.
        Returns False if validation fails or ES write fails.
        Invalid alerts go to logs/invalid_alerts.jsonl (via validator).
        ES write failures go to logs/alerts_buffer.jsonl.
        """
        # ── Validate before sending to ES ─────────────────────────────
        is_valid, error = validate_alert(alert)
        if not is_valid:
            log.warning(
                "Alert rejected by validator: %s (rule=%s)",
                error,
                alert.get("rule", {}).get("id", "unknown"),
            )
            return False

        # ── Write to ES ───────────────────────────────────────────────
        try:
            self.es.index(index=self._index_name(), body=alert)
            log.info(
                "Alert indexed: [%s] %s",
                alert.get("rule", {}).get("severity", "?"),
                alert.get("rule", {}).get("id", "?"),
            )
            return True
        except Exception as exc:
            log.error("ES alert write failed: %s — buffering to disk", exc)
            self._buffer_to_disk(alert)
            return False

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
                    self.es.index(index=self._index_name(), body=alert)
                    resent += 1
                except Exception:
                    break  # ES still down

            if resent == len(lines):
                open(self._buffer_path, "w").close()
                log.info("Flushed %d buffered alerts to ES", resent)
            elif resent > 0:
                with open(self._buffer_path, "w") as f:
                    f.writelines(lines[resent:])
                log.info("Partially flushed %d/%d buffered alerts", resent, len(lines))
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
