"""
detection_engine/alert_template.py
Installs the Elasticsearch index template for siem-alerts-* indices.

Ensures all alert fields have explicit mappings so dynamic mapping
never produces type conflicts (e.g. "N/A" in a date field).

Call ensure_template() once at engine startup.
"""

from __future__ import annotations

import logging
from elasticsearch import Elasticsearch

log = logging.getLogger("detection_engine.alert_template")

TEMPLATE_NAME = "siem-alerts-template"
INDEX_PATTERN = "siem-alerts-*"

TEMPLATE_BODY = {
    "index_patterns": [INDEX_PATTERN],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "rule": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "description": {"type": "text"},
                    }
                },
                "event": {
                    "properties": {
                        "count": {"type": "integer"},
                    }
                },
                "host": {
                    "properties": {
                        "name": {"type": "keyword"},
                    }
                },
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                    }
                },
                "user": {
                    "properties": {
                        "name": {"type": "keyword"},
                    }
                },
                "matched": {
                    "properties": {
                        "event_ids": {"type": "keyword"},
                    }
                },
                "engine": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "version": {"type": "keyword"},
                    }
                },
                "correlation": {
                    "properties": {
                        "parent_rule": {"type": "keyword"},
                        "reason": {"type": "text"},
                        "brute_force_attempt_count": {"type": "integer"},
                    }
                },
                "suppressed_until": {"type": "date"},
                "mitre": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "tactic": {"type": "keyword"},
                        "technique": {"type": "keyword"},
                    }
                },
                "evidence": {
                    "properties": {
                        "raw_events": {"type": "text"},
                        "group_key": {"type": "keyword"},
                        "window_seconds": {"type": "integer"},
                        "first_seen": {"type": "date"},
                        "last_seen": {"type": "date"},
                        "unique_users": {"type": "keyword"},
                        "unique_ips": {"type": "ip"},
                    }
                },
            }
        },
    },
}


def ensure_template(es: Elasticsearch) -> bool:
    """
    Create or update the siem-alerts index template.

    Returns True if the template was created/updated, False on error.
    Idempotent — safe to call every startup.
    """
    try:
        # Check if template already exists
        if es.indices.exists_index_template(name=TEMPLATE_NAME):
            log.info("Alert index template '%s' already exists", TEMPLATE_NAME)
            # Update it anyway to pick up schema changes
            es.indices.put_index_template(name=TEMPLATE_NAME, body=TEMPLATE_BODY)
            log.info("Alert index template '%s' updated", TEMPLATE_NAME)
            return True

        es.indices.put_index_template(name=TEMPLATE_NAME, body=TEMPLATE_BODY)
        log.info("Alert index template '%s' created", TEMPLATE_NAME)
        return True

    except Exception as exc:
        log.warning(
            "Could not create alert template '%s': %s  "
            "(alerts will use dynamic mapping — may cause type errors)",
            TEMPLATE_NAME,
            exc,
        )
        return False
