"""
detection_engine/elastic_client.py
Handles ALL communication with Elasticsearch for reading events.

Responsibilities:
  - Fetch events from siem-raw-* where tags contains "ready_for_detection"
  - search_after pagination using [@timestamp, _id] sort
  - Checkpoint extraction

MUST NOT contain detection logic.
MUST NOT aggregate on raw text fields — always use .keyword suffix.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from elasticsearch import Elasticsearch

from . import config

log = logging.getLogger("detection_engine.elastic_client")


class ESReader:
    """Stateless Elasticsearch reader for the detection engine poll loop."""

    def __init__(self, es_client: Elasticsearch,
                 index_pattern: str = config.ES_RAW_INDEX):
        self.es = es_client
        self.index_pattern = index_pattern

    def poll(
        self,
        last_processed_id: Optional[str],
        last_processed_timestamp: Optional[str],
        batch_size: int = config.ES_POLL_BATCH_SIZE,
    ) -> List[dict]:
        """
        Fetch new events from Elasticsearch since the last checkpoint.

        Uses search_after for stateless, no-duplicate pagination.
        Only returns events tagged "ready_for_detection".

        Returns an empty list if no new events or ES is unavailable.
        NEVER uses from+size — that reprocesses events on restart.
        """
        query: dict = {
            "size": batch_size,
            "sort": [
                {"@timestamp": {"order": "asc"}},
                
            ],
            "query": {
                "bool": {
                    "must": [
                        {"match_all": {}},
                    ],
                    "filter": [
                        {"term": {"tags": "ready_for_detection"}},
                        {"range": {"@timestamp": {"gte": "now-2m"}}}
                    ],
                }
            },
        }

        # Resume from checkpoint
        if last_processed_timestamp and last_processed_id:
            query["search_after"] = [last_processed_timestamp]

        try:
            response = self.es.search(index=self.index_pattern, body=query)
            hits = response.get("hits", {}).get("hits", [])
            if hits:
                log.debug("Fetched %d events from ES", len(hits))
            return hits
        except Exception as exc:
            log.error("ES poll error: %s", exc)
            return []

    @staticmethod
    def get_last_checkpoint(hits: List[dict]) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract checkpoint values from the last hit in the batch.
        Returns (last_id, last_timestamp).
        """
        if not hits:
            return None, None
        last = hits[-1]
        return last["_source"].get("@timestamp")
