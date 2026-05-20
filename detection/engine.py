import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from elasticsearch import Elasticsearch


# ── Config ────────────────────────────────────────────────────────────────────

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
SOURCE_INDEX = os.getenv("SOURCE_INDEX", "siem-raw-*")
DETECTIONS_INDEX = os.getenv("DETECTIONS_INDEX", "detections-alerts")


# ── Rule name constants ───────────────────────────────────────────────────────

RULE_SSH_BRUTEFORCE_BY_IP = "ssh_bruteforce_by_ip"
RULE_PASSWORD_SPRAY_BY_IP = "password_spray_by_ip"
RULE_USER_BRUTEFORCE_BY_USER = "user_bruteforce_by_user"
RULE_DISTRIBUTED_BRUTEFORCE = "distributed_bruteforce_by_user"
RULE_SUDO_BRUTEFORCE_BY_USER = "sudo_bruteforce_by_user"
RULE_SSH_SUCCESS_AFTER_FAILURES = "ssh_success_after_failures"


# ── Thresholds / windows / suppression ───────────────────────────────────────

SSH_BF_WINDOW_SECONDS = 60
SSH_BF_THRESHOLD = 5
SSH_BF_SUPPRESS_MINUTES = 10

SPRAY_WINDOW_SECONDS = 120
SPRAY_THRESHOLD_DISTINCT_USERS = 5
SPRAY_SUPPRESS_MINUTES = 15

USER_BF_WINDOW_SECONDS = 180
USER_BF_THRESHOLD = 6
USER_BF_SUPPRESS_MINUTES = 20

DIST_BF_WINDOW_SECONDS = 300
DIST_BF_THRESHOLD_DISTINCT_IPS = 5
DIST_BF_SUPPRESS_MINUTES = 30

SUDO_BF_WINDOW_SECONDS = 180
SUDO_BF_THRESHOLD = 3
SUDO_BF_SUPPRESS_MINUTES = 20

SSH_SEQ_FAILURE_THRESHOLD = 3
SSH_SEQ_LOOKBACK_SECONDS = 300
SSH_SEQ_SUPPRESS_MINUTES = 30

PASS_B_SINGLE_IP_DOMINANCE_THRESHOLD = 0.80
TERMS_AGG_SIZE = 500


# ── Elasticsearch client ──────────────────────────────────────────────────────

def get_client() -> Elasticsearch:
    if ES_USER and ES_PASSWORD:
        return Elasticsearch(
            ES_HOST,
            basic_auth=(ES_USER, ES_PASSWORD),
            verify_certs=False,
        )
    return Elasticsearch(
        ES_HOST,
        verify_certs=False,
    )


# ── Shared helpers ────────────────────────────────────────────────────────────

def kw(field: str) -> str:
    return f"{field}.keyword"


def _es_terms_agg(
    must_terms: list,
    range_start: datetime,
    range_end: datetime,
    exists_fields: list,
    agg_field: str,
    agg_name: str,
    sub_agg: Optional[dict] = None,
    size: int = TERMS_AGG_SIZE,
) -> list:
    client = get_client()

    must_clauses = list(must_terms)
    must_clauses.append({
        "range": {
            "@timestamp": {
                "gte": range_start.isoformat(),
                "lte": range_end.isoformat(),
            }
        }
    })

    for field in exists_fields:
        must_clauses.append({"exists": {"field": field}})

    agg_body = {
        "terms": {
            "field": agg_field,
            "size": size,
        }
    }

    if sub_agg:
        agg_body["aggs"] = sub_agg

    query = {
        "size": 0,
        "query": {"bool": {"must": must_clauses}},
        "aggs": {agg_name: agg_body},
    }

    try:
        resp = client.search(index=SOURCE_INDEX, body=query)
        return (
            resp.get("aggregations", {})
            .get(agg_name, {})
            .get("buckets", [])
        )
    except Exception as exc:
        print(f"[_es_terms_agg] Elasticsearch error on agg '{agg_name}': {exc}")
        return []


def _fingerprint(parts: list) -> str:
    seed = ":".join(str(p) for p in parts)
    return hashlib.sha256(seed.encode()).hexdigest()


def _fingerprint_hourly(anchor_ts: datetime, rule_name: str, *entities) -> str:
    hour_bucket = anchor_ts.strftime("%Y%m%dT%H")
    return _fingerprint([rule_name, *entities, hour_bucket])


def _is_suppressed(client: Elasticsearch, fingerprint: str, suppress_minutes: int) -> bool:
    suppress_since = (
        datetime.now(timezone.utc) - timedelta(minutes=suppress_minutes)
    ).isoformat()

    try:
        resp = client.search(
            index=DETECTIONS_INDEX,
            body={
                "size": 1,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {kw("fingerprint"): fingerprint}},
                            {"range": {"created_at": {"gte": suppress_since}}},
                        ]
                    }
                },
            },
        )
        return resp["hits"]["total"]["value"] > 0
    except Exception:
        return False


def _emit_alert(
    rule_name: str,
    severity: str,
    title: str,
    details: dict,
    fingerprint: str,
    src_ip: Optional[str] = None,
    user_name: Optional[str] = None,
    suppress_minutes: int = 10,
) -> bool:
    client = get_client()

    if _is_suppressed(client, fingerprint, suppress_minutes):
        return False

    now = datetime.now(timezone.utc)
    doc = {
        "rule_name": rule_name,
        "severity": severity,
        "title": title,
        "fingerprint": fingerprint,
        "created_at": now.isoformat(),
        "@timestamp": now.isoformat(),
        "details": details,
    }

    if src_ip:
        doc["source_ip"] = src_ip
    if user_name:
        doc["user"] = user_name

    try:
        client.index(index=DETECTIONS_INDEX, document=doc)
        print(f"  ✅ Alert created: [{severity.upper()}] {title}")
        return True
    except Exception as exc:
        print(f"  ❌ Failed to index alert: {exc}")
        return False


def get_anchor_timestamp() -> datetime:
    return datetime.now(timezone.utc)


# ── Detectors ─────────────────────────────────────────────────────────────────

def detect_ssh_bruteforce_by_ip(anchor_ts: datetime) -> dict:
    rule_name = RULE_SSH_BRUTEFORCE_BY_IP
    window_seconds = SSH_BF_WINDOW_SECONDS
    threshold = SSH_BF_THRESHOLD
    suppress_mins = SSH_BF_SUPPRESS_MINUTES

    window_start = anchor_ts - timedelta(seconds=window_seconds)
    window_end = anchor_ts

    buckets = _es_terms_agg(
        must_terms=[{"term": {"event_type": "failed_login"}}],
        range_start=window_start,
        range_end=window_end,
        exists_fields=["source_ip"],
        agg_field=kw("source_ip"),
        agg_name="by_ip",
    )

    candidates = [b for b in buckets if b["doc_count"] >= threshold]
    created = 0

    for b in candidates:
        src_ip = b["key"]
        count = b["doc_count"]
        fp = _fingerprint_hourly(anchor_ts, rule_name, src_ip)

        details = {
            "detector": rule_name,
            "source_ip": src_ip,
            "count": count,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "anchor_ts": anchor_ts.isoformat(),
        }

        title = f"Possible SSH brute-force — {count} failed logins from {src_ip} in {window_seconds}s"

        if _emit_alert(
            rule_name=rule_name,
            severity="medium",
            title=title,
            details=details,
            fingerprint=fp,
            src_ip=src_ip,
            suppress_minutes=suppress_mins,
        ):
            created += 1

    print(f"[{rule_name}] candidates={len(candidates)} alerts_created={created}")
    return {"candidates": len(candidates), "alerts_created": created}


def detect_password_spray_by_ip(anchor_ts: datetime) -> dict:
    rule_name = RULE_PASSWORD_SPRAY_BY_IP
    window_seconds = SPRAY_WINDOW_SECONDS
    threshold = SPRAY_THRESHOLD_DISTINCT_USERS
    suppress_mins = SPRAY_SUPPRESS_MINUTES

    window_start = anchor_ts - timedelta(seconds=window_seconds)
    window_end = anchor_ts

    sub_agg = {
        "distinct_users": {"cardinality": {"field": kw("user")}},
        "top_users": {"terms": {"field": kw("user"), "size": 5}},
    }

    buckets = _es_terms_agg(
        must_terms=[{"term": {"event_type": "failed_login"}}],
        range_start=window_start,
        range_end=window_end,
        exists_fields=["source_ip", "user"],
        agg_field=kw("source_ip"),
        agg_name="by_ip",
        sub_agg=sub_agg,
    )

    candidates = [
        b for b in buckets
        if b.get("distinct_users", {}).get("value", 0) >= threshold
    ]
    created = 0

    for b in candidates:
        src_ip = b["key"]
        distinct_users = b.get("distinct_users", {}).get("value", 0)
        example_users = [u["key"] for u in b.get("top_users", {}).get("buckets", [])]
        fp = _fingerprint_hourly(anchor_ts, rule_name, src_ip)

        details = {
            "detector": rule_name,
            "source_ip": src_ip,
            "distinct_users": distinct_users,
            "example_users": example_users,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "anchor_ts": anchor_ts.isoformat(),
        }

        title = f"Password spraying suspected — {distinct_users} users targeted from {src_ip} in {window_seconds}s"

        if _emit_alert(
            rule_name=rule_name,
            severity="medium",
            title=title,
            details=details,
            fingerprint=fp,
            src_ip=src_ip,
            suppress_minutes=suppress_mins,
        ):
            created += 1

    print(f"[{rule_name}] candidates={len(candidates)} alerts_created={created}")
    return {"candidates": len(candidates), "alerts_created": created}


def detect_user_bruteforce_by_user(anchor_ts: datetime) -> dict:
    rule_name = RULE_USER_BRUTEFORCE_BY_USER
    window_seconds = USER_BF_WINDOW_SECONDS
    threshold = USER_BF_THRESHOLD
    suppress_mins = USER_BF_SUPPRESS_MINUTES

    window_start = anchor_ts - timedelta(seconds=window_seconds)
    window_end = anchor_ts

    sub_agg = {
        "top_source_ips": {"terms": {"field": kw("source_ip"), "size": 5}},
        "distinct_source_ips": {"cardinality": {"field": kw("source_ip")}},
    }

    buckets = _es_terms_agg(
        must_terms=[{"term": {"event_type": "failed_login"}}],
        range_start=window_start,
        range_end=window_end,
        exists_fields=["user"],
        agg_field=kw("user"),
        agg_name="by_user",
        sub_agg=sub_agg,
    )

    candidates = []
    for b in buckets:
        if b["doc_count"] < threshold:
            continue
        distinct_ips = b.get("distinct_source_ips", {}).get("value", 0)
        if distinct_ips >= DIST_BF_THRESHOLD_DISTINCT_IPS:
            continue
        candidates.append(b)

    created = 0

    for b in candidates:
        user_name = b["key"]
        count = b["doc_count"]
        top_src_ips = [u["key"] for u in b.get("top_source_ips", {}).get("buckets", [])]
        distinct_ips = b.get("distinct_source_ips", {}).get("value", 0)
        fp = _fingerprint_hourly(anchor_ts, rule_name, user_name)

        details = {
            "detector": rule_name,
            "user": user_name,
            "count": count,
            "threshold": threshold,
            "top_source_ips": top_src_ips,
            "distinct_source_ips": distinct_ips,
            "window_seconds": window_seconds,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "anchor_ts": anchor_ts.isoformat(),
        }

        title = f"Account targeted — {count} failed logins for user {user_name} in {window_seconds}s"

        if _emit_alert(
            rule_name=rule_name,
            severity="high",
            title=title,
            details=details,
            fingerprint=fp,
            user_name=user_name,
            suppress_minutes=suppress_mins,
        ):
            created += 1

    print(f"[{rule_name}] candidates={len(candidates)} alerts_created={created}")
    return {"candidates": len(candidates), "alerts_created": created}


def detect_distributed_bruteforce_by_user(anchor_ts: datetime) -> dict:
    rule_name = RULE_DISTRIBUTED_BRUTEFORCE
    window_seconds = DIST_BF_WINDOW_SECONDS
    threshold = DIST_BF_THRESHOLD_DISTINCT_IPS
    suppress_mins = DIST_BF_SUPPRESS_MINUTES

    window_start = anchor_ts - timedelta(seconds=window_seconds)
    window_end = anchor_ts

    sub_agg = {
        "distinct_ips": {"cardinality": {"field": kw("source_ip")}},
    }

    buckets = _es_terms_agg(
        must_terms=[{"term": {"event_type": "failed_login"}}],
        range_start=window_start,
        range_end=window_end,
        exists_fields=["user", "source_ip"],
        agg_field=kw("user"),
        agg_name="by_user",
        sub_agg=sub_agg,
    )

    candidates = [
        b for b in buckets
        if b.get("distinct_ips", {}).get("value", 0) >= threshold
    ]
    created = 0

    for b in candidates:
        user_name = b["key"]
        distinct_ips = b.get("distinct_ips", {}).get("value", 0)
        fp = _fingerprint_hourly(anchor_ts, rule_name, user_name)

        details = {
            "detector": rule_name,
            "user": user_name,
            "distinct_ips": distinct_ips,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "anchor_ts": anchor_ts.isoformat(),
        }

        title = f"Distributed brute-force — {distinct_ips} source IPs targeting user {user_name} in {window_seconds}s"

        if _emit_alert(
            rule_name=rule_name,
            severity="high",
            title=title,
            details=details,
            fingerprint=fp,
            user_name=user_name,
            suppress_minutes=suppress_mins,
        ):
            created += 1

    print(f"[{rule_name}] candidates={len(candidates)} alerts_created={created}")
    return {"candidates": len(candidates), "alerts_created": created}


def detect_sudo_bruteforce_by_user(anchor_ts: datetime) -> dict:
    rule_name = RULE_SUDO_BRUTEFORCE_BY_USER
    window_seconds = SUDO_BF_WINDOW_SECONDS
    threshold = SUDO_BF_THRESHOLD
    suppress_mins = SUDO_BF_SUPPRESS_MINUTES

    window_start = anchor_ts - timedelta(seconds=window_seconds)
    window_end = anchor_ts

    buckets = _es_terms_agg(
        must_terms=[{"term": {"event_type": "sudo_failed"}}],
        range_start=window_start,
        range_end=window_end,
        exists_fields=["user"],
        agg_field=kw("user"),
        agg_name="by_user",
    )

    candidates = [b for b in buckets if b["doc_count"] >= threshold]
    created = 0

    for b in candidates:
        user_name = b["key"]
        count = b["doc_count"]
        fp = _fingerprint_hourly(anchor_ts, rule_name, user_name)

        details = {
            "detector": rule_name,
            "user": user_name,
            "count": count,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "anchor_ts": anchor_ts.isoformat(),
        }

        title = f"Repeated sudo failures — {count} failures for user {user_name} in {window_seconds}s"

        if _emit_alert(
            rule_name=rule_name,
            severity="high",
            title=title,
            details=details,
            fingerprint=fp,
            user_name=user_name,
            suppress_minutes=suppress_mins,
        ):
            created += 1

    print(f"[{rule_name}] candidates={len(candidates)} alerts_created={created}")
    return {"candidates": len(candidates), "alerts_created": created}


def detect_ssh_success_after_failures(anchor_ts: datetime) -> dict:
    rule_name = RULE_SSH_SUCCESS_AFTER_FAILURES
    lookback_seconds = SSH_SEQ_LOOKBACK_SECONDS
    failure_threshold = SSH_SEQ_FAILURE_THRESHOLD
    suppress_mins = SSH_SEQ_SUPPRESS_MINUTES

    window_start = anchor_ts - timedelta(seconds=lookback_seconds)
    window_end = anchor_ts

    total_created = 0
    pass_a_ip_candidates = 0
    pass_b_user_candidates = 0

    fail_buckets_ip = _es_terms_agg(
        must_terms=[{"term": {"event_type": "failed_login"}}],
        range_start=window_start,
        range_end=window_end,
        exists_fields=["source_ip"],
        agg_field=kw("source_ip"),
        agg_name="by_ip",
        sub_agg={
            "top_users": {"terms": {"field": kw("user"), "size": 5}}
        },
    )

    attacker_ips = {
        b["key"]: {
            "failures": b["doc_count"],
            "users": [u["key"] for u in b.get("top_users", {}).get("buckets", [])],
        }
        for b in fail_buckets_ip
        if b["doc_count"] >= failure_threshold
    }

    pass_a_covered_users: set[str] = set()

    if attacker_ips:
        success_buckets_ip = _es_terms_agg(
            must_terms=[{"term": {"event_type": "success_login"}}],
            range_start=window_start,
            range_end=window_end,
            exists_fields=["source_ip"],
            agg_field=kw("source_ip"),
            agg_name="by_ip",
            sub_agg={
                "top_users": {"terms": {"field": kw("user"), "size": 5}}
            },
        )

        success_by_ip = {
            b["key"]: {
                "successes": b["doc_count"],
                "users": [u["key"] for u in b.get("top_users", {}).get("buckets", [])],
            }
            for b in success_buckets_ip
        }

        hit_ips = set(attacker_ips.keys()) & set(success_by_ip.keys())
        pass_a_ip_candidates = len(hit_ips)

        for src_ip in hit_ips:
            failures = attacker_ips[src_ip]["failures"]
            fail_users = attacker_ips[src_ip]["users"]
            success_users = success_by_ip[src_ip]["users"]
            involved_user = (success_users or fail_users or [None])[0]

            for u in set(fail_users + success_users):
                pass_a_covered_users.add(u)

            fp = _fingerprint_hourly(anchor_ts, rule_name, src_ip)
            details = {
                "detector": rule_name,
                "anchor_type": "ip",
                "source_ip": src_ip,
                "failures": failures,
                "failure_threshold": failure_threshold,
                "involved_users": list(set(fail_users + success_users)),
                "window_seconds": lookback_seconds,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "anchor_ts": anchor_ts.isoformat(),
            }

            title = f"SSH success after failures — {failures} failures then success from {src_ip}"

            if _emit_alert(
                rule_name=rule_name,
                severity="high",
                title=title,
                details=details,
                fingerprint=fp,
                src_ip=src_ip,
                user_name=involved_user,
                suppress_minutes=suppress_mins,
            ):
                total_created += 1

    print(f"[{rule_name}] Pass A — ip_candidates={pass_a_ip_candidates}")

    fail_buckets_user = _es_terms_agg(
        must_terms=[{"term": {"event_type": "failed_login"}}],
        range_start=window_start,
        range_end=window_end,
        exists_fields=["user"],
        agg_field=kw("user"),
        agg_name="by_user",
        sub_agg={
            "distinct_ips": {"cardinality": {"field": kw("source_ip")}},
            "top_ips": {"terms": {"field": kw("source_ip"), "size": 10}},
        },
    )

    attacker_users = {}
    for b in fail_buckets_user:
        if b["doc_count"] < failure_threshold:
            continue

        user_name = b["key"]
        total_fails = b["doc_count"]
        distinct_ips = b.get("distinct_ips", {}).get("value", 0)
        top_ips = b.get("top_ips", {}).get("buckets", [])

        if user_name in pass_a_covered_users:
            continue
        if distinct_ips < 2:
            continue
        if top_ips:
            top_ip_count = top_ips[0]["doc_count"]
            dominance = top_ip_count / total_fails if total_fails > 0 else 0
            if dominance >= PASS_B_SINGLE_IP_DOMINANCE_THRESHOLD:
                continue

        attacker_users[user_name] = {
            "failures": total_fails,
            "distinct_ips": distinct_ips,
            "attacker_ips": {u["key"] for u in top_ips},
        }

    if attacker_users:
        success_buckets_user = _es_terms_agg(
            must_terms=[{"term": {"event_type": "success_login"}}],
            range_start=window_start,
            range_end=window_end,
            exists_fields=["user"],
            agg_field=kw("user"),
            agg_name="by_user",
            sub_agg={
                "top_ips": {"terms": {"field": kw("source_ip"), "size": 5}}
            },
        )

        success_by_user = {
            b["key"]: {
                "successes": b["doc_count"],
                "success_ips": [u["key"] for u in b.get("top_ips", {}).get("buckets", [])],
            }
            for b in success_buckets_user
        }

        hit_users = set(attacker_users.keys()) & set(success_by_user.keys())
        pass_b_user_candidates = len(hit_users)

        for user_name in hit_users:
            failures = attacker_users[user_name]["failures"]
            distinct_ips = attacker_users[user_name]["distinct_ips"]
            attacker_ips_set = attacker_users[user_name]["attacker_ips"]
            success_ips = success_by_user[user_name]["success_ips"]

            success_src_ip = next(
                (ip for ip in success_ips if ip in attacker_ips_set),
                success_ips[0] if success_ips else None,
            )

            fp = _fingerprint_hourly(anchor_ts, rule_name, user_name, "user_anchor")
            details = {
                "detector": rule_name,
                "anchor_type": "user",
                "user": user_name,
                "source_ip": success_src_ip,
                "failures": failures,
                "distinct_ips": distinct_ips,
                "failure_threshold": failure_threshold,
                "success_ips": success_ips,
                "window_seconds": lookback_seconds,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "anchor_ts": anchor_ts.isoformat(),
            }

            title = f"SSH success after failures — {failures} failures across {distinct_ips} IPs then success for user {user_name}"

            if _emit_alert(
                rule_name=rule_name,
                severity="high",
                title=title,
                details=details,
                fingerprint=fp,
                src_ip=success_src_ip,
                user_name=user_name,
                suppress_minutes=suppress_mins,
            ):
                total_created += 1

    print(f"[{rule_name}] Pass B — user_candidates={pass_b_user_candidates}")
    print(f"[{rule_name}] total alerts_created={total_created}")

    return {
        "pass_a_ip_candidates": pass_a_ip_candidates,
        "pass_b_user_candidates": pass_b_user_candidates,
        "alerts_created": total_created,
    }


# ── Orchestrator ──────────────────────────────────────────────────────────────

DETECTORS = [
    ("ssh_bruteforce_by_ip", detect_ssh_bruteforce_by_ip),
    ("password_spray_by_ip", detect_password_spray_by_ip),
    ("user_bruteforce_by_user", detect_user_bruteforce_by_user),
    ("distributed_bruteforce_by_user", detect_distributed_bruteforce_by_user),
    ("sudo_bruteforce_by_user", detect_sudo_bruteforce_by_user),
    ("ssh_success_after_failures", detect_ssh_success_after_failures),
]


def main():
    anchor_ts = get_anchor_timestamp()
    print(f"[bruteforce_rule] Starting correlation run. Anchor={anchor_ts.isoformat()}")

    total_created = 0
    summary_parts = []

    for name, detector_fn in DETECTORS:
        try:
            result = detector_fn(anchor_ts)
        except Exception as exc:
            print(f"[bruteforce_rule] UNHANDLED error in detector '{name}': {exc}")
            result = {"alerts_created": 0}

        created = result.get("alerts_created", 0)
        total_created += created

        if "pass_a_ip_candidates" in result:
            summary_parts.append(
                f"{name}(passA={result['pass_a_ip_candidates']},passB={result['pass_b_user_candidates']},created={created})"
            )
        else:
            summary_parts.append(
                f"{name}(cand={result.get('candidates', 0)},created={created})"
            )

    summary = " | ".join(summary_parts)
    print(
        f"✅ Correlation run complete."
        f" Anchor={anchor_ts.isoformat()}"
        f" TotalCreated={total_created}"
        f" — {summary}"
    )


if __name__ == "__main__":
    main()