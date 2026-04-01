"""
Generates 200 realistic simulated AWS CloudTrail log entries,
including 15 anomalous ones, and saves to sample_cloudtrail.json.
"""
import json, random, os
from datetime import datetime, timedelta

random.seed(42)

NORMAL_USERS = ["alice", "bob", "charlie", "diana", "eve", "frank"]
NORMAL_IPS   = ["10.0.1.10", "10.0.1.11", "10.0.2.5", "192.168.1.20", "192.168.1.21"]
NORMAL_ACTIONS = [
    "s3:GetObject", "s3:PutObject", "ec2:DescribeInstances",
    "ec2:StartInstances", "iam:ListUsers", "rds:DescribeDBInstances",
    "cloudwatch:GetMetricData", "lambda:InvokeFunction"
]
RESOURCES = [
    "arn:aws:s3:::company-data-bucket",
    "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890",
    "arn:aws:iam::123456789012:user/alice",
    "arn:aws:rds:us-east-1:123456789012:db:prod-db",
    "arn:aws:lambda:us-east-1:123456789012:function:processor"
]

base_time = datetime(2024, 3, 15, 9, 0, 0)
logs = []

def make_entry(user, ip, action, status, resource, ts, extra=None):
    entry = {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "userName": user},
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": action,
        "sourceIPAddress": ip,
        "requestParameters": {"bucketName": resource.split(":::")[-1] if "s3" in resource else None},
        "responseElements": {"status": status},
        "resources": [{"ARN": resource}],
        "errorCode": "AccessDenied" if status == "FAILED" else None
    }
    if extra:
        entry.update(extra)
    return entry

# --- 185 normal entries ---
for i in range(185):
    ts     = base_time + timedelta(minutes=random.randint(0, 480), seconds=random.randint(0, 59))
    user   = random.choice(NORMAL_USERS)
    ip     = random.choice(NORMAL_IPS)
    action = random.choice(NORMAL_ACTIONS)
    status = random.choices(["SUCCESS", "FAILED"], weights=[9, 1])[0]
    res    = random.choice(RESOURCES)
    logs.append(make_entry(user, ip, action, status, res, ts))

# --- 15 anomalous entries ---
anomalies = [
    # 1-3: Off-hours root logins from unusual IP
    *[make_entry("root", "203.0.113.55", "iam:CreateUser",
                 "SUCCESS", RESOURCES[2],
                 base_time + timedelta(hours=random.choice([0,1,2,3,22,23])),
                 {"anomaly": True, "anomaly_type": "off_hours_root_login"})
      for _ in range(3)],

    # 4-6: Mass S3 deletions
    *[make_entry(random.choice(NORMAL_USERS), "185.220.101.42",
                 "s3:DeleteObject", "SUCCESS",
                 "arn:aws:s3:::company-data-bucket",
                 base_time + timedelta(minutes=random.randint(500,510)),
                 {"anomaly": True, "anomaly_type": "mass_s3_deletion",
                  "requestParameters": {"bucketName": "company-data-bucket",
                                        "key": f"sensitive/file_{i}.csv"}})
      for i in range(3)],

    # 7-9: Privilege escalation attempts
    *[make_entry("charlie", "10.99.0.1", "iam:AttachUserPolicy",
                 "SUCCESS", "arn:aws:iam::123456789012:user/charlie",
                 base_time + timedelta(hours=2, minutes=i*5),
                 {"anomaly": True, "anomaly_type": "privilege_escalation",
                  "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}})
      for i in range(3)],

    # 10-12: Brute-force login failures
    *[make_entry("admin", "91.108.4.100", "ConsoleLogin",
                 "FAILED", "arn:aws:iam::123456789012:user/admin",
                 base_time + timedelta(minutes=30 + i*2),
                 {"anomaly": True, "anomaly_type": "brute_force",
                  "errorCode": "FailedAuthentication"})
      for i in range(3)],

    # 13-15: Unusual data exfiltration (large GetObject)
    *[make_entry("eve", "198.51.100.77", "s3:GetObject",
                 "SUCCESS", "arn:aws:s3:::company-data-bucket",
                 base_time + timedelta(hours=21, minutes=i*10),
                 {"anomaly": True, "anomaly_type": "data_exfiltration",
                  "additionalEventData": {"bytesTransferredOut": random.randint(500_000_000, 2_000_000_000)}})
      for i in range(3)],
]
logs.extend(anomalies)
random.shuffle(logs)

out_path = os.path.join(os.path.dirname(__file__), "sample_cloudtrail.json")
with open(out_path, "w") as f:
    json.dump(logs, f, indent=2)

print(f"Generated {len(logs)} log entries → {out_path}")
