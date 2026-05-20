import os
import logging
from elasticsearch import Elasticsearch, exceptions

logger = logging.getLogger(__name__)

SIEM_ES_URL = os.getenv("SIEM_ES_URL", "http://localhost:9200")

# Shared module-level client
es_client = Elasticsearch([SIEM_ES_URL])

def get_es_client() -> Elasticsearch:
    return es_client

def es_search(index: str, query: dict, size: int = 50):
    """Helper to perform search safely, returning empty list on failure or missing index."""
    try:
        if not es_client.indices.exists(index=index):
            logger.warning(f"Index pattern {index} does not exist.")
            return {"hits": [], "total": 0}
            
        res = es_client.search(index=index, body=query, size=size)
        return {"hits": res["hits"]["hits"], "total": res["hits"]["total"]["value"]}
    except exceptions.NotFoundError:
        return {"hits": [], "total": 0}
    except Exception as e:
        logger.error(f"Elasticsearch search failed: {e}")
        return {"hits": [], "total": 0, "error": str(e)}

def es_count(index: str, query: dict = None):
    """Helper to perform count safely."""
    if query is None:
        query = {"query": {"match_all": {}}}
    try:
        if not es_client.indices.exists(index=index):
            return 0
        res = es_client.count(index=index, body=query)
        return res["count"]
    except Exception as e:
        logger.error(f"Elasticsearch count failed: {e}")
        return 0
