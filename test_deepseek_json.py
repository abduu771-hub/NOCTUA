import os
import json
from openai import OpenAI

api_key = os.getenv("DEEPSEEK_API_KEY")
if not api_key:
    raise RuntimeError("DEEPSEEK_API_KEY is not set")

client = OpenAI(
    api_key=api_key,
    base_url="https://api.deepseek.com",
)

response = client.chat.completions.create(
    model="deepseek-chat",
    response_format={"type": "json_object"},
    messages=[
        {
            "role": "system",
            "content": """
You are the AI incident analyst inside ABUR - SIEM.

Return ONLY valid json.
Do not use markdown.
Do not invent evidence.
Do not invent usernames, IPs, domains, malware names, files, commands, or timestamps.
Use only the incident data provided.
If something is missing, say "not available".

Required json keys:
summary,
attack_story,
severity_reasoning,
confidence,
evidence,
recommended_actions,
investigation_steps,
possible_false_positives,
soc_ticket_summary.
""",
        },
        {
            "role": "user",
            "content": """
Analyze this incident as json:

{
  "incident_type": "Account Compromise With Malware Activity",
  "severity": "CRITICAL",
  "user": "malware_acct1",
  "source_ip": "172.20.36.201",
  "host": "470d8c32270f",
  "related_incident_types": [
    "account_compromise",
    "IDS / Malware Network Activity"
  ],
  "evidence": [
    "Repeated failed SSH login attempts for user malware_acct1",
    "Successful SSH login after brute-force activity",
    "Suricata IDS malware signature from source IP 172.20.36.201"
  ]
}
""",
        },
    ],
    stream=False,
)

content = response.choices[0].message.content
analysis = json.loads(content)
print(json.dumps(analysis, indent=2))
