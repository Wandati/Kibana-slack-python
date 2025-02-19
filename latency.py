# Description: This script fetches CPU and Latency alerts from Elasticsearch and sends them to Slack.
import requests
from dotenv import load_dotenv
import os
import json
import re
import time
from datetime import datetime

load_dotenv()

# Load environment variables
ELASTIC_URL = os.getenv("ELASTIC_URL")
ES_API_KEY = os.getenv("ES_API_KEY")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# Validate Slack payload format
def validate_slack_payload(payload):
    """Validate Slack message payload format"""
    required_keys = ["channel", "blocks"]
    if not all(key in payload for key in required_keys):
        raise ValueError("Missing required keys in Slack payload")
    
    if not payload["blocks"]:
        raise ValueError("Empty blocks in Slack payload")
    
    return True


def send_slack_alert(cpu_alerts, latency_alerts, batch_size=10, delay=2):
    """
    Send CPU and Latency alerts to Slack in batches to avoid exceeding message limits.
    
    :param cpu_alerts: List of CPU alerts
    :param latency_alerts: List of Latency alerts
    :param batch_size: Number of alerts to send per batch (default: 10)
    :param delay: Delay in seconds between batches (default: 2 seconds)
    """
    all_alerts = cpu_alerts + latency_alerts  # Combine all alerts
    total_batches = (len(all_alerts) + batch_size - 1) // batch_size  # Calculate total batches

    print(f"Total alerts: {len(all_alerts)} (sending in {total_batches} batches of {batch_size})")

    for i in range(0, len(all_alerts), batch_size):
        batch = all_alerts[i:i + batch_size]  # Get alerts for current batch

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = {
            "channel": "#devops",
            "text": "🚨 Performance Alerts 🚨",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 Performance Alerts (Batch {i//batch_size + 1}/{total_batches}) 🚨", "emoji": True}
                },
                {
                    "type": "context",
                    "elements": [{"type": "plain_text", "text": f"Alert Time: {current_time}", "emoji": True}]
                },
                {"type": "divider"}
            ]
        }

        # Add alerts in this batch
        for alert in batch:
            alert_type = "🔥 CPU Alert" if "host" in alert else "⏳ Latency Alert"
            text = (
                f"*Host:* `{alert['host']}`\n*CPU Usage:* {alert['raw_value']:.2f}%" if "host" in alert
                else f"*Service:* `{alert['service']}`\n*Response Time:* {alert['raw_value']:.2f}s"
            )
            payload["blocks"].append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{alert_type}:*\n{text}"}})
        
        payload["blocks"].append({"type": "divider"})  # Add a divider at the end

        # Print payload for debugging
        print(json.dumps(payload, indent=2))

        try:
            response = requests.post(
                SLACK_WEBHOOK_URL,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            print(f"Batch {i//batch_size + 1} sent successfully!")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send batch {i//batch_size + 1}: {e}")

        # Wait before sending the next batch
        if i + batch_size < len(all_alerts):
            print(f"Waiting {delay} seconds before sending next batch...")
            time.sleep(delay)

    print("All alerts sent successfully! 🚀")

def extract_service_name(alert_reason):
    """
    Extract service name from 'kibana.alert.reason' field.
    """
    match = re.search(r"service:\s*([\w-]+)", alert_reason)
    return match.group(1) if match else "Unknown"

# Elasticsearch query to fetch CPU & Latency alerts
url = f'{ELASTIC_URL}/.alerts-*/_search'
headers = {
    "Authorization": f'Apikey {ES_API_KEY}',
    "Content-Type": "application/json"
}

query = {
    "size": 10000,
    "query": {
        "bool": {
            "must": [
                {"term": {"kibana.alert.status": "active"}},
                {"range": {"@timestamp": {"gte": "now-1h/h", "lte": "now", "format": "strict_date_time"}}}
            ]
        }
    },
    "_source": [
        "@timestamp",
        "host.name",
        "kibana.alert.rule.name",
        "kibana.alert.status",
        "kibana.alert.reason",
        "kibana.alert.evaluation.values"
    ]
}

# Fetch data from Elasticsearch
response = requests.get(url, headers=headers, json=query)
data = response.json()

# Process alerts separately for CPU and Latency
cpu_alerts = []
latency_alerts = []

for hit in data['hits']['hits']:
    source = hit["_source"]
    alert_name = source["kibana.alert.rule.name"]
    alert_reason = source["kibana.alert.reason"]
    timestamp = source["@timestamp"]

    # CPU Alerts: Must contain host.name and evaluation values
    if "host.name" in source and "kibana.alert.evaluation.values" in source:
        cpu_usage = source["kibana.alert.evaluation.values"][0] * 100  # Convert to percentage
        cpu_alerts.append({
            "host": source["host.name"],
            "alert": alert_name,
            "reason":alert_reason,
            "raw_value": cpu_usage,
            "timestamp": timestamp
        })

    # Latency Alerts: Do not have host.name or evaluation values
    elif "Latency" in alert_name:
        service_name = extract_service_name(alert_reason)
        match = re.search(r"Avg\. latency is ([\d.]+) s", alert_reason)
        latency_value = float(match.group(1)) if match else 0.0  # Extract latency in seconds

        latency_alerts.append({
            "service": service_name,
            "alert": alert_name,
            "reason": alert_reason,
            "raw_value": latency_value,
            "timestamp": timestamp
        })

# Sort alerts (CPU by usage %, Latency by response time)
cpu_alerts.sort(key=lambda x: x["raw_value"], reverse=True)
latency_alerts.sort(key=lambda x: x["raw_value"], reverse=True)

# Print summary
print(f'Affected hosts (CPU): {len(cpu_alerts)}')
print(f'Affected services (Latency): {len(latency_alerts)}')
print('-' * 50)

# Display CPU alerts
for alert in cpu_alerts:
    print(f' CPU - {alert["host"]}: {alert["raw_value"]:.2f}% ')

print('-' * 50)

# Display Latency alerts
for alert in latency_alerts:
    print(f'Latency - {alert["service"]}: {alert["raw_value"]:.2f}s ')

print('-' * 50)

# Send alerts to Slack
send_slack_alert(cpu_alerts, latency_alerts)
