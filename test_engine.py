import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, '/home/abdu/SIEM-AI')

from detection_engine.models import Event
from detection_engine.rule_engine import RuleEngine

def make_web_event(action, url, status, ip="192.168.1.100", agent="curl/7.68.0", host="web-server-01"):
    raw_log = f'{ip} - - [{datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {url} HTTP/1.1" {status} 500 "-" "{agent}"'
    return Event(
        event_type=action,
        source_ip=ip,
        source_port=None,
        user=None,
        effective_user=None,
        timestamp=datetime.now(timezone.utc),
        raw_log=raw_log,
        program="nginx",
        command_line=None,
        host=host,
        es_doc_id="mock_id",
        es_index="mock_index"
    )

print("Starting verification test...")
engine = RuleEngine()

# Test Path Traversal
print("\n--- Testing Path Traversal ---")
for i in range(3):
    alerts = engine.process_event(make_web_event("web_path_traversal_attempt", f"/etc/passwd?i={i}", 403))
    if alerts:
        print("Alert triggered!")
        alert = alerts[0]
        print(f"URL: {alert.get('url', {}).get('original')}")
        print(f"Status Code: {alert.get('http', {}).get('response', {}).get('status_code')}")
        print(f"User Agent: {alert.get('user_agent', {}).get('original')}")
        print(f"Tags: {alert.get('tags')}")
        print(f"Description: {alert.get('rule', {}).get('description')}")

# Test SQL Injection
print("\n--- Testing SQL Injection ---")
for i in range(3):
    alerts = engine.process_event(make_web_event("web_sql_injection_attempt", f"/login?user=admin' OR {i}={i}--", 500))
    if alerts:
        print("Alert triggered!")
        alert = alerts[0]
        print(f"URL: {alert.get('url', {}).get('original')}")
        print(f"Tags: {alert.get('tags')}")
        print(f"Description: {alert.get('rule', {}).get('description')}")

# Test 404 Scanning (Frequency)
print("\n--- Testing 404 Scanning ---")
for i in range(20):
    alerts = engine.process_event(make_web_event("web_404", f"/random-path-{i}", 404))
    if alerts:
        print("Alert triggered!")
        alert = alerts[0]
        print(f"URL: {alert.get('url', {}).get('original')}")
        print(f"Tags: {alert.get('tags')}")
        print(f"Description: {alert.get('rule', {}).get('description')}")

print("\nVerification Complete.")
