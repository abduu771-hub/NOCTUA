"""
detection_engine/elastic_client.py
Handles ALL communication with Elasticsearch for reading events.

Responsibilities:
  - Fetch events from siem-raw-* where tags contains "ready_for_detection"
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

    def __init__(
        self,
        es_client: Elasticsearch,
        index_pattern: str = config.ES_RAW_INDEX,
    ) -> None:
        self.es = es_client
        self.index_pattern = index_pattern

    def poll(
        self,
        last_processed_id: Optional[str],
        last_processed_timestamp: Optional[str],
        batch_size: int = config.ES_POLL_BATCH_SIZE,
    ) -> List[dict]:
        """
        Fetch new ready_for_detection events from Elasticsearch.

        This is the original simple/live polling behavior:
          - Only read events tagged ready_for_detection
          - Use @timestamp checkpoint
          - Use a small recent window when no checkpoint exists
          - Sort by @timestamp asc
          - Return ES hits to main.py

        Returns an empty list if no new events or ES is unavailable.
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
                        {"term": {"tags.keyword": "ready_for_detection"}},
                    ],
                }
            },
        }

        if last_processed_timestamp:
            query["query"]["bool"]["filter"].append(
                {
                    "range": {
                        "@timestamp": {
                            "gt": last_processed_timestamp,
                        }
                    }
                }
            )
            log.debug(
                "Polling ready events after checkpoint timestamp=%s id=%s",
                last_processed_timestamp,
                last_processed_id,
            )
        else:
            query["query"]["bool"]["filter"].append(
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-2m",
                        }
                    }
                }
            )
            log.info("No checkpoint found; polling ready events from now-2m")

        try:
            response = self.es.search(index=self.index_pattern, body=query)
            hits = response.get("hits", {}).get("hits", [])
            log.debug("Fetched %d ready events from ES", len(hits))
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
        return last.get("_id"), last.get("_source", {}).get("@timestamp")
