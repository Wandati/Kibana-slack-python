# Elasticsearch Alert Monitor

A Python script that monitors CPU usage and latency alerts from Elasticsearch and sends notifications to Slack.

## Overview
This tool fetches active alerts from Elasticsearch, specifically looking for:
- High CPU usage alerts across multiple hosts
- High latency alerts for various services
- Formats and sends alert notifications to a Slack channel

## Prerequisites

- Python 3.7+
- Access to an Elasticsearch instance
- Slack workspace with webhook configuration
- Following Python packages:
  ```txt
  requests
  python-dotenv
  ```

## Installation

1. Clone or download the project files
2. Create a `.env` file in the project root:
   ```ini
   ELASTIC_URL=https://your-elasticsearch-url
   ES_API_KEY=your-elasticsearch-api-key  
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
   ```
3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## How It Works

### Alert Fetching
The script queries Elasticsearch for active alerts from the past hour using:
```python
query = {
    "size": 10000,
    "query": {
        "bool": {
            "must": [
                {"term": {"kibana.alert.status": "active"}},
                {"range": {"@timestamp": {"gte": "now-1h/h", "lte": "now"}}}
            ]
        }
    }
}
```

### Alert Processing
1. **CPU Alerts**
   - Extracts host name and CPU usage percentage
   - Converts raw values to percentages
   - Sorts by usage in descending order

2. **Latency Alerts** 
   - Extracts service name and response time
   - Parses latency values from alert messages
   - Sorts by latency in descending order

### Slack Notifications
Sends formatted messages containing:
- Alert timestamp
- Separate sections for CPU and latency alerts
- Per-alert details including:
  - Host/Service name
  - Alert type
  - Usage/Latency values
- Visual formatting with emojis and dividers

## Usage

Run the script using:
```bash
python latency.py
```

### Console Output
The script displays:
```
Affected hosts (CPU): X
Affected services (Latency): Y
--------------------------------------------------
CPU - hostname1: 95.50%
CPU - hostname2: 85.20%
--------------------------------------------------
Latency - service1: 2.50s
Latency - service2: 1.80s
--------------------------------------------------
```

### Slack Output
Notifications are sent to the configured Slack channel with:
- 🚨 Alert header
- Current timestamp
- Formatted sections for CPU and latency alerts
- Color-coded and emoji-enhanced messages

## Error Handling

The script includes error handling for:
- Missing environment variables
- Failed Elasticsearch queries  
- Invalid alert data formats
- Slack notification failures

## Customization

You can modify:
- Alert time window (default: 1 hour)
- Query size limit (default: 10000)
- Slack message formatting
- Alert thresholds and filtering

## Troubleshooting

1. **No Alerts Shown**
   - Verify Elasticsearch connection
   - Check API key permissions
   - Confirm alert indices exist

2. **Slack Notifications Fail**
   - Validate webhook URL
   - Check network connectivity
   - Verify channel permissions

## Contributing

Feel free to:
- Open issues for bugs
- Suggest improvements
- Submit pull requests

