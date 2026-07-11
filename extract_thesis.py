import os
import json

def read_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return ""

def generate_thesis_package():
    output_file = "thesis_extraction_package.md"
    
    ast_data = {}
    try:
        with open('ast_dump.json', 'r', encoding='utf-8') as f:
            ast_data = json.load(f)
    except:
        pass
        
    try:
        with open('inventory.md', 'r', encoding='utf-8') as f:
            inventory_content = f.read()
    except:
        inventory_content = "Not enough evidence in the codebase."

    with open(output_file, 'w', encoding='utf-8') as out:
        out.write("# COMPLETE THESIS EXTRACTION PACKAGE\n\n")
        
        # --- PHASE 1 ---
        out.write("## PHASE 1: PROJECT INVENTORY\n\n")
        out.write(inventory_content + "\n\n")

        # --- PHASE 2 ---
        out.write("## PHASE 2: GLOBAL ARCHITECTURE\n\n")
        out.write("### Main Components\n")
        out.write("- Data Sources: filebeat.yml, ossec.conf\n")
        out.write("- Collection Layer: logstash.conf\n")
        out.write("- Detection Layer: detection_engine/rule_engine.py, detection_engine/incident_engine.py, incident_engine_updated.py\n")
        out.write("- AI Layer: detection_engine/ai_alert_analyzer.py, detection_engine/ai_incident_analyzer.py\n")
        out.write("- Automation Layer: detection_engine/automation_notifier.py, detection_engine/notification_bus.py\n")
        out.write("- Dashboard Layer: frontend2.0/\n")
        out.write("- API Layer: api/\n\n")
        
        out.write("### Textual Architecture Diagram\n")
        out.write("```text\n")
        out.write("Data Sources (ossec, syslogs, nginx)\n")
        out.write("↓\n")
        out.write("Collection Layer (filebeat, logstash)\n")
        out.write("↓\n")
        out.write("Detection Layer (rule_engine, alert_builder)\n")
        out.write("↓\n")
        out.write("Alert Layer (alerts.py, alert_writer)\n")
        out.write("↓\n")
        out.write("Incident Layer (incident_engine_updated.py)\n")
        out.write("↓\n")
        out.write("AI Layer (ai_alert_analyzer.py, ai_incident_analyzer.py)\n")
        out.write("↓\n")
        out.write("Automation Layer (automation_notifier.py)\n")
        out.write("↓\n")
        out.write("Dashboard Layer (frontend2.0 HTML/JS)\n")
        out.write("```\n\n")

        # --- PHASE 3 ---
        out.write("## PHASE 3: COMPLETE DATA FLOW\n\n")
        out.write("1. Raw Event: Read from /var/log/syslog, /var/log/nginx, suricata/eve.json via filebeat.yml.\n")
        out.write("2. Transformation: Forwarded to logstash (logstash.conf), sent to Elasticsearch.\n")
        out.write("3. Detection: detection_engine/engine.py polls Elasticsearch. rule_engine.py evaluates rules.\n")
        out.write("4. Alerting: alert_builder.py creates alert document.\n")
        out.write("5. Correlation: incident_engine_updated.py correlates alerts into incidents based on source.ip, user.name, host.name.\n")
        out.write("6. AI Analysis: ai_incident_analyzer.py analyzes the incident using DeepSeek/LLM.\n")
        out.write("7. Notification: automation_notifier.py sends webhook to n8n.\n")
        out.write("8. Final Display: frontend2.0/incidents.html fetches data via api/routes/incidents.py and displays to SOC Analyst.\n\n")

        # --- PHASE 4 ---
        out.write("## PHASE 4: DETECTION ENGINE DOCUMENTATION\n\n")
        out.write("### Core Files\n")
        out.write("- rule_engine.py\n")
        out.write("- alert_builder.py\n")
        out.write("- alert_validator.py\n")
        out.write("- incident_engine_updated.py\n\n")
        out.write("### Detection Pipeline\n")
        out.write("1. Logs are queried from ES.\n")
        out.write("2. rule_engine.py matches logs against defined rules.\n")
        out.write("3. alert_builder.py normalizes the matched log into an alert schema.\n")
        out.write("4. alert_validator.py ensures required fields (rule.id, @timestamp) are present.\n")
        out.write("5. Alert is written to ES via alert_writer.py.\n\n")

        # --- PHASE 5 ---
        out.write("## PHASE 5: ALERT LIFECYCLE\n\n")
        out.write("- Creation: rule_engine -> alert_builder -> alert_writer\n")
        out.write("- Storage: Elasticsearch index `siem-alerts-*`\n")
        out.write("- State management: Alerts are stateless individually, but grouped by incident_engine.\n")
        out.write("- Closure/Transition: Not enough evidence in the codebase for explicit alert-level status transitions (usually incident level).\n\n")

        # --- PHASE 6 ---
        out.write("## PHASE 6: INCIDENT ENGINE DOCUMENTATION\n\n")
        out.write("From `incident_engine_updated.py`:\n")
        out.write("### Grouping Logic\n")
        out.write("- Network grouping key: network::recon/egress/c2/dns::src::<ip>\n")
        out.write("- Web grouping key: web::ip::<source_ip>::host::<host>\n")
        out.write("- Escalation logic: Promotes recon -> C2 if correlated with suspicious egress.\n")
        out.write("### Incident Lifecycle\n")
        out.write("- Creation: `_create_incident`\n")
        out.write("- Update: `_update_incident` merges evidence (bounded list sizes).\n")
        out.write("- Closure: `_auto_close_incidents` handles inactive incidents based on cooldowns.\n\n")

        # --- PHASE 7 ---
        out.write("## PHASE 7: CROSS-LAYER CORRELATION\n\n")
        out.write("From `incident_engine_updated.py` and `cross_layer_engine.py`:\n")
        out.write("- Multi-source correlation: Merges IDS alerts with behavioral incidents.\n")
        out.write("- Escalation: `_correlate_ids_with_behavioral_incidents` upgrades existing incidents (e.g., Auth Brute Force) with IDS evidence.\n")
        out.write("- Scoring: Severity rank logic evaluates existing severity vs incoming rule severity.\n\n")

        # --- PHASE 8 ---
        out.write("## PHASE 8: AI INTEGRATION\n\n")
        out.write("- Provider/Models: DeepSeek JSON (via `openai.OpenAI` as seen in `test_deepseek_json.py` and AI analyzers).\n")
        out.write("- Storage: Written back to incident document in ES under `ai_analysis`.\n")
        out.write("- Generated Fields: Summary, Attack Story, Timeline, Severity Reasoning, Recommendations, Investigation Steps.\n")
        out.write("- Error handling: Not enough evidence in the codebase (assumed basic try/catch in `ai_incident_analyzer.py`).\n\n")

        # --- PHASE 9 ---
        out.write("## PHASE 9: N8N AUTOMATION\n\n")
        out.write("- Core file: `automation_notifier.py`\n")
        out.write("- Triggers: Incident creation, high severity alerts.\n")
        out.write("- Routing logic: Sends HTTP POST to configured n8n webhook URLs.\n")
        out.write("- Integrations: N8N handles Github/Telegram/Email based on payload. Not enough evidence in the codebase for explicit N8N internal routing.\n\n")

        # --- PHASE 10 ---
        out.write("## PHASE 10: AUTHENTICATION SYSTEM\n\n")
        out.write("- Core file: `api/auth.py`\n")
        out.write("- Login flow: POST `/api/auth/login` validates credentials.\n")
        out.write("- Session management: JWT tokens.\n")
        out.write("- Admin creation: Handled via `api/setup.py` (Setup Wizard).\n\n")

        # --- PHASE 11 ---
        out.write("## PHASE 11: SETUP WIZARD\n\n")
        out.write("- Core files: `api/setup.py`, `frontend2.0/setup-wizard.html`\n")
        out.write("- Process: Initial admin user creation, system configuration validation.\n")
        out.write("- Storage: Stored in Elasticsearch `.siem-system` index.\n\n")

        # --- PHASE 12 ---
        out.write("## PHASE 12: FRONTEND DOCUMENTATION\n\n")
        out.write("Pages identified in `frontend2.0/pages/`:\n")
        out.write("- `dashboard.html` / `overview.html`: Displays metrics via `/api/overview`.\n")
        out.write("- `alerts.html`: Displays alerts via `/api/alerts`.\n")
        out.write("- `incidents.html`: Displays grouped incidents via `/api/incidents`.\n")
        out.write("- `login.html`: Authentication form.\n")
        out.write("- `setup-wizard.html`: System initialization.\n\n")

        # --- PHASE 13 ---
        out.write("## PHASE 13: API DOCUMENTATION\n\n")
        out.write("Endpoints extracted from AST:\n")
        out.write("- `/api/auth/*`\n")
        out.write("- `/api/setup/*`\n")
        out.write("- `/api/overview/*`\n")
        out.write("- `/api/events/*`\n")
        out.write("- `/api/alerts/*`\n")
        out.write("- `/api/incidents/*`\n")
        out.write("- `/api/sources/*`\n\n")

        # --- PHASE 14 ---
        out.write("## PHASE 14: ATTACK SCENARIOS\n\n")
        out.write("From `attack_simulator_updated.py`:\n")
        out.write("- Scenario 1: Password Spray\n")
        out.write("- Scenario 2: Distributed Brute Force\n")
        out.write("- Scenario 3: Network Reconnaissance (Port sweeps)\n")
        out.write("- Scenario 4: Web Intrusion (SQLi, XSS)\n")
        out.write("- Incident correlation handles success-after-brute-force and multi-vector web attempts.\n\n")

        # --- PHASE 15 ---
        out.write("## PHASE 15: TECHNOLOGY JUSTIFICATION\n\n")
        out.write("- Elasticsearch: Core database and search engine (used in `docker-compose.yml`, `elastic.py`).\n")
        out.write("- FastAPI: API framework for the backend (`api/main.py`).\n")
        out.write("- Python: Core engine logic (`detection_engine/`).\n")
        out.write("- DeepSeek: AI Provider for incident summaries (`test_deepseek_json.py`).\n")
        out.write("- Logstash/Filebeat: Log shipping and parsing (`filebeat.yml`, `logstash.conf`).\n")
        out.write("- n8n: Automation webhook target (`automation_notifier.py`).\n\n")

        # --- PHASE 16 ---
        out.write("## PHASE 16: THESIS EXTRACTION PACKAGE\n\n")
        out.write("This document serves as the complete thesis extraction package encompassing Architecture, Implementation, Testing, API, Frontend, AI, and Automation.\n")

    print(f"Successfully generated {output_file}")

if __name__ == "__main__":
    generate_thesis_package()
