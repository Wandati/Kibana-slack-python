# A Python script to monitor and alert on high CPU usage and latency in Elasticsearch and Kibana.
import requests
from elasticsearch import Elasticsearch
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
    """
    all_alerts = cpu_alerts + latency_alerts
    total_batches = (len(all_alerts) + batch_size - 1) // batch_size

    print(f"Total alerts: {len(all_alerts)} (sending in {total_batches} batches of {batch_size})")

    for i in range(0, len(all_alerts), batch_size):
        batch = all_alerts[i:i + batch_size]

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

        for alert in batch:
            alert_type = "🔥 CPU Alert" if "host" in alert else "⏳ Latency Alert"
            text = (
                f"*Host:* `{alert['host']}`\n*CPU Usage:* {alert['raw_value']:.2f}%" if "host" in alert
                else f"*Service:* `{alert['service']}`\n*Response Time:* {alert['raw_value']:.2f}s"
            )
            payload["blocks"].append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{alert_type}:*\n{text}"}})
        
        payload["blocks"].append({"type": "divider"})

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

        if i + batch_size < len(all_alerts):
            print(f"Waiting {delay} seconds before sending next batch...")
            time.sleep(delay)

    print("All alerts sent successfully! 🚀")

def get_cpu_alerts():
    """
    Get CPU alerts using the new aggregation-based approach
    """
    try:
        # Connect to Elasticsearch with API key authentication
        es = Elasticsearch(ELASTIC_URL, api_key=ES_API_KEY)
        
        # Define the aggregation query for CPU metrics
        query = {
            "size": 0,
            "query": {
                "match_all": {}
            },
            "aggs": {
                "servers": {
                    "terms": {"field": "host.name", "size": 1000},
                    "aggs": {
                        "avg_user_pct": {"avg": {"field": "system.cpu.user.pct"}},
                        "avg_system_pct": {"avg": {"field": "system.cpu.system.pct"}},
                        "max_cpu_cores": {"max": {"field": "system.cpu.cores"}},
                        "calculated_cpu_usage": {
                            "bucket_script": {
                                "buckets_path": {
                                    "user_avg": "avg_user_pct",
                                    "system_avg": "avg_system_pct",
                                    "cores_max": "max_cpu_cores"
                                },
                                "script": "(params.user_avg + params.system_avg) / params.cores_max"
                            }
                        }
                    }
                }
            }
        }

        response = es.search(index="metricbeat-*", body=query)
        cpu_alerts = []

        for host in response["aggregations"]["servers"]["buckets"]:
            host_name = host["key"]
            cpu_usage = host["calculated_cpu_usage"]["value"] * 100
            if cpu_usage > 95:
                cpu_alerts.append({
                    "host": host_name,
                    "raw_value": cpu_usage,
                    "timestamp": datetime.now().isoformat()
                })
                # print(f"🔥 High CPU Usage on {host_name} ({cpu_usage:.2f}%)")

        return cpu_alerts

    except Exception as e:
        print(f"❌ Error querying Elasticsearch for CPU metrics: {e}")
        return []

def get_latency_alerts():
    """
    Get latency alerts from Elasticsearch
    """
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

    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        latency_alerts = []

        for hit in data['hits']['hits']:
            source = hit["_source"]
            alert_name = source["kibana.alert.rule.name"]
            alert_reason = source["kibana.alert.reason"]
            
            if "Latency" in alert_name:
                service_name = extract_service_name(alert_reason)
                match = re.search(r"Avg\. latency is ([\d.]+) s", alert_reason)
                latency_value = float(match.group(1)) if match else 0.0

                latency_alerts.append({
                    "service": service_name,
                    "alert": alert_name,
                    "reason": alert_reason,
                    "raw_value": latency_value,
                    "timestamp": source["@timestamp"]
                })

        return sorted(latency_alerts, key=lambda x: x["raw_value"], reverse=True)

    except Exception as e:
        print(f"❌ Error querying Elasticsearch for latency alerts: {e}")
        return []

def extract_service_name(alert_reason):
    """Extract service name from 'kibana.alert.reason' field."""
    match = re.search(r"service:\s*([\w-]+)", alert_reason)
    return match.group(1) if match else "Unknown"

def main():
    """Main function to run the monitoring and alerting"""
    print("Starting monitoring checks...")
    
    # Get CPU alerts
    cpu_alerts = get_cpu_alerts()
    print(f"\nFound {len(cpu_alerts)} servers with high CPU usage")
    
    # Get latency alerts
    latency_alerts = get_latency_alerts()
    print(f"Found {len(latency_alerts)} services with high latency")
    
    # Print summary
    print(f'\nAffected hosts (CPU): {len(cpu_alerts)}')
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

    # # Send alerts to Slack
    if cpu_alerts or latency_alerts:
      send_slack_alert(cpu_alerts, latency_alerts)

if __name__ == "__main__":
    main()