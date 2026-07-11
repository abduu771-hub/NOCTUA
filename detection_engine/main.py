#!/usr/bin/env python3
"""
detection_engine/main.py — Entry point for the SIEM-AI Detection Engine v2.0

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
"""

from __future__ import annotations

import logging
import os
import sys
import time

from elasticsearch import Elasticsearch

from . import config
from .alert_template import ensure_template
from .alert_writer import AlertWriter
from .elastic_client import ESReader
from .incident_engine import IncidentEngine
from .models import event_from_es_hit
from .rule_engine import RuleEngine
from .rules import ALL_RULES
from .state import StateManager
from .ai_alert_analyzer import AIAlertAnalyzer
# ── Logging setup ─────────────────────────────────────────────────────────────
# Réduire les logs Elasticsearch
logging.getLogger("elastic_transport.transport").setLevel(logging.WARNING)
logging.getLogger("elasticsearch").setLevel(logging.WARNING)

os.makedirs(config.LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=config.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE),
    ],
)
log = logging.getLogger("detection_engine.main")


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    # ── 1. ES connection ──────────────────────────────────────────────────
    es_host = config.ES_HOST
    if not es_host:
        log.error("ES_HOST environment variable is required")
        sys.exit(1)

    log.info("Connecting to Elasticsearch at %s", es_host)
    es = Elasticsearch([es_host], retry_on_timeout=True, max_retries=3)

    try:
        info = es.info()
        cluster = info.get("cluster_name", info.get("name", "unknown"))
        log.info("Connected to ES cluster: %s", cluster)
    except Exception as exc:
        log.error("Cannot connect to Elasticsearch: %s", exc)
        sys.exit(1)

    # ── 1b. Install alert index template ──────────────────────────────────
    ensure_template(es)

    # ── 2. Component initialisation ───────────────────────────────────────
    es_reader = ESReader(es)
    alert_writer = AlertWriter(es)
    incident_engine = IncidentEngine(es)
    alert_ai = AIAlertAnalyzer(es)
    state_manager = StateManager()
    rule_engine = RuleEngine()

    # Restore watch list from persisted state
    wl_snap = state_manager.watch_list_snapshot
    if wl_snap:
        rule_engine.watch_list.from_dict(wl_snap)
        log.info("Restored %d watch-list entries from state", len(wl_snap))

    last_processed_id = state_manager.last_processed_id
    last_processed_timestamp = state_manager.last_processed_timestamp

    log.info("Detection engine started.  Poll interval: %ds", config.POLL_INTERVAL_SECONDS)
    log.info("Rules loaded: %s", [r.rule_id for r in ALL_RULES])

    if last_processed_id:
        log.info("Resuming from checkpoint: %s @ %s", last_processed_id, last_processed_timestamp)
    else:
        log.info("No checkpoint — processing all available events")

    # ── 3. Poll loop ──────────────────────────────────────────────────────
    while True:
        cycle_start = time.time()
        cycle_events = 0
        cycle_alerts = 0

        try:
            # Flush previously-buffered alerts
            alert_writer.flush_buffer()

            # Fetch new events
            hits = es_reader.poll(last_processed_id, last_processed_timestamp)

            for hit in hits:
                cycle_events += 1

                # ── 3a. Map ES hit → Event ────────────────────────────
                try:
                    event = event_from_es_hit(hit)
                except ValueError as ve:
                    _log_dropped(hit, str(ve))
                    last_processed_id = hit["_id"]
                    last_processed_timestamp = hit["_source"].get("@timestamp")
                    continue
                except Exception as exc:
                    log.error("Event mapping error on doc %s: %s", hit.get("_id", "?"), exc)
                    last_processed_id = hit["_id"]
                    last_processed_timestamp = hit["_source"].get("@timestamp")
                    continue

                # ── 3b. Skip unknown events ───────────────────────────
                if event.event_type == "unknown":
                    _log_unknown(event)
                    last_processed_id = event.es_doc_id
                    last_processed_timestamp = hit["_source"].get("@timestamp")
                    continue

                # ── 3c. Rule engine ───────────────────────────────────
                alerts = rule_engine.process_event(event)

                for alert in alerts:
                    alert_doc_id = alert_writer.write(alert)
                    if alert_doc_id:
                        cycle_alerts += 1
                        alert_ai.analyze_and_update(
                            index=alert_writer._index_name(),
                            doc_id=alert_doc_id,
                            alert_doc=alert,
                        )
                        incident_engine.process_alert(alert)

                # ── 3d. Advance checkpoint ────────────────────────────
                last_processed_id = event.es_doc_id
                last_processed_timestamp = hit["_source"].get("@timestamp")

            # ── 4. Post-cycle maintenance ─────────────────────────────
            rule_engine.cleanup()
            incident_engine.run_auto_close_cycle()

            # ── 5. Persist state ──────────────────────────────────────
            if cycle_events > 0 or cycle_alerts > 0:
                state_manager.save(
                    last_id=last_processed_id,
                    last_timestamp=last_processed_timestamp,
                    events_processed=cycle_events,
                    alerts_fired=cycle_alerts,
                    watch_list_snapshot=rule_engine.watch_list.to_dict(),
                )
                log.info("Cycle: %d events, %d alerts", cycle_events, cycle_alerts)

        except KeyboardInterrupt:
            log.info("Engine stopped by user (Ctrl+C)")
            break

        except Exception as exc:
            log.error("Unhandled exception in main loop: %s", exc, exc_info=True)

        # Sleep for the remainder of the poll interval
        elapsed = time.time() - cycle_start
        sleep_time = max(0, config.POLL_INTERVAL_SECONDS - elapsed)
        time.sleep(sleep_time)

    log.info("Engine shutdown complete.")


# ── Diagnostic loggers ────────────────────────────────────────────────────────

def _log_dropped(hit: dict, reason: str) -> None:
    try:
        with open(config.DROPPED_EVENTS_LOG, "a") as f:
            msg = hit.get("_source", {}).get("message", "<no message>")
            f.write(f"[{reason}] {msg}\n")
    except Exception:
        pass


def _log_unknown(event) -> None:
    try:
        with open(config.UNKNOWN_EVENTS_LOG, "a") as f:
            f.write(f"{event.raw_log}\n")
    except Exception:
        pass


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
