"""
generate_logs.py

A standalone script to generate 200 fresh sample logs with randomised anomalies 
on each run. Always ensures the project has live-looking, demo-ready data.
"""

import json
import random
import os
from datetime import datetime, timedelta
from pathlib import Path

LOGS_DIR = Path(__file__).resolve().parent / "logs"

def gen_timestamp():
    """Generate ISO timestamp within the last hour."""
    now = datetime.utcnow()
    offset = random.randint(0, 3600)
    dt = now - timedelta(seconds=offset)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_normal_log():
    return {
        "eventTime": gen_timestamp(),
        "userIdentity": {"userName": random.choice(["alice", "bob", "dev_api", "system", "deploy_bot"])},
        "sourceIPAddress": f"10.0.{random.randint(1,5)}.{random.randint(1,250)}",
        "eventName": random.choice(["DescribeInstances", "ListBuckets", "GetCallerIdentity", "CreateLogStream", "ConsoleLogin"]),
        "responseElements": {"status": "SUCCESS"},
        "anomaly": False
    }

def generate_anomalous_log():
    anomalies = [
        {
            "userIdentity": {"userName": "system_admin"},
            "sourceIPAddress": f"{random.randint(1,255)}.{random.randint(1,255)}.100.100",
            "eventName": "DeleteVpc",
            "errorCode": "AccessDenied",
            "responseElements": {"status": "FAILED"},
            "anomaly": True,
            "anomaly_type": "DestructiveAction"
        },
        {
            "userIdentity": {"userName": "unknown_actor"},
            "sourceIPAddress": "193.20.100.44",
            "eventName": "StopLogging",
            "responseElements": {"status": "SUCCESS"},
            "anomaly": True,
            "anomaly_type": "DefenseEvasion"
        },
        {
            "userIdentity": {"userName": "backup_service"},
            "sourceIPAddress": "45.2.19.1",
            "eventName": "CreateUser",
            "responseElements": {"status": "SUCCESS"},
            "anomaly": True,
            "anomaly_type": "PrivilegeEscalation"
        },
        {
            "userIdentity": {"userName": "compromised_token"},
            "sourceIPAddress": "104.22.44.1",
            "eventName": "DeleteBucket",
            "responseElements": {"status": "SUCCESS"},
            "anomaly": True,
            "anomaly_type": "DataExfiltration"
        }
    ]
    log = random.choice(anomalies).copy()
    log["eventTime"] = gen_timestamp()
    return log

def main():
    os.makedirs(LOGS_DIR, exist_ok=True)
    logs = []
    
    # Generate 190 standard API calls
    for _ in range(190):
        logs.append(generate_normal_log())
        
    # Inject 10 anomalous/malicious API calls
    for _ in range(10):
        logs.append(generate_anomalous_log())
        
    # Shuffle for realism
    random.shuffle(logs)
    
    payload = {"Records": logs}
    output_path = LOGS_DIR / f"demo_cloudtrail_{int(datetime.utcnow().timestamp())}.json"
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        
    print(f"✅ Generated 200 logs (190 normal, 10 anomalous) at: {output_path}")

if __name__ == "__main__":
    main()
