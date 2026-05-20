"""
detection_engine/state.py
Engine state persistence — survives restarts without reprocessing events.

Stores:
  - last_processed_id / last_processed_timestamp (ES checkpoint)
  - total_events_processed / total_alerts_fired (counters)
  - watch_list_snapshot (active watches)

Uses atomic write (temp file + os.replace) to prevent corruption.
MUST NOT evaluate rules.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from . import config

log = logging.getLogger("detection_engine.state")


class StateManager:
    """Persist and restore engine state across restarts."""

    def __init__(self, state_file: str = config.STATE_FILE_PATH) -> None:
        self._state_file = state_file
        self.state = self._load()

    # ── Load / save ───────────────────────────────────────────────────────

    def _load(self) -> dict:
        if not os.path.exists(self._state_file):
            log.info("No state file found — starting fresh")
            return self._empty_state()

        try:
            with open(self._state_file, "r") as f:
                data = json.load(f)
            log.info("Restored state from %s", self._state_file)
            return data
        except Exception as exc:
            log.warning("Could not load %s (%s) — starting fresh", self._state_file, exc)
            return self._empty_state()

    def save(
        self,
        last_id: Optional[str],
        last_timestamp: Optional[str],
        events_processed: int,
        alerts_fired: int,
        watch_list_snapshot: dict,
    ) -> None:
        """
        Persist current state.  Called after each successful poll cycle.
        Atomic write: write to .tmp then os.replace.
        """
        state = {
            "last_processed_id": last_id,
            "last_processed_timestamp": last_timestamp,
            "total_events_processed": self.state.get("total_events_processed", 0) + events_processed,
            "total_alerts_fired": self.state.get("total_alerts_fired", 0) + alerts_fired,
            "engine_started_at": self.state.get("engine_started_at"),
            "watch_list_snapshot": watch_list_snapshot,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

        tmp_path = self._state_file + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp_path, self._state_file)
            self.state = state
        except Exception as exc:
            log.error("Failed to save state: %s", exc)

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def last_processed_id(self) -> Optional[str]:
        return self.state.get("last_processed_id")

    @property
    def last_processed_timestamp(self) -> Optional[str]:
        return self.state.get("last_processed_timestamp")

    @property
    def watch_list_snapshot(self) -> dict:
        return self.state.get("watch_list_snapshot", {})

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _empty_state() -> dict:
        return {
            "last_processed_id": None,
            "last_processed_timestamp": None,
            "total_events_processed": 0,
            "total_alerts_fired": 0,
            "engine_started_at": datetime.now(timezone.utc).isoformat(),
            "watch_list_snapshot": {},
        }
