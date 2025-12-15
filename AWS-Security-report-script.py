import boto3
import pandas as pd
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# =============================
# CONFIG
# =============================
REGION = "ap-south-1"
LAST_7_DAYS = datetime.now(timezone.utc) - timedelta(days=7)

session = boto3.Session(region_name=REGION)

ec2 = session.client("ec2")
cloudwatch = session.client("cloudwatch")
backup = session.client("backup")
inspector = session.client("inspector2")
sts = session.client("sts")

ACCOUNT_ID = sts.get_caller_identity()["Account"]

# =============================
# EC2 INSTANCES (ID + NAME)
# =============================
instances = {}

paginator = ec2.get_paginator("describe_instances")
for page in paginator.paginate():
    for reservation in page["Reservations"]:
        for inst in reservation["Instances"]:
            instance_id = inst["InstanceId"]

            name = "N/A"
            for tag in inst.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
                    break

            instances[instance_id] = {
                "InstanceId": instance_id,
                "InstanceName": name
            }

print(f"Discovered EC2 instances: {len(instances)}")

if not instances:
    raise RuntimeError("No EC2 instances found. Check region or AWS profile.")

# =============================
# BACKUP CHECK (AWS Backup)
# =============================
protected_instances = set()

paginator = backup.get_paginator("list_protected_resources")
for page in paginator.paginate():
    for r in page["Results"]:
        if r["ResourceType"] == "EC2":
            instance_id = r["ResourceArn"].split("/")[-1]
            protected_instances.add(instance_id)

# =============================
# CLOUDWATCH ALARMS
# =============================
alarm_map = defaultdict(list)
alarm_triggered_last_week = defaultdict(bool)

paginator = cloudwatch.get_paginator("describe_alarms")
for page in paginator.paginate():
    for alarm in page["MetricAlarms"]:
        instance_id = None

        for d in alarm.get("Dimensions", []):
            if d["Name"] == "InstanceId":
                instance_id = d["Value"]

        if not instance_id:
            continue

        alarm_name = alarm["AlarmName"].lower()
        alarm_map[instance_id].append(alarm_name)

        if (
            alarm["StateValue"] == "ALARM"
            and alarm["StateUpdatedTimestamp"] >= LAST_7_DAYS
        ):
            alarm_triggered_last_week[instance_id] = True

# =============================
# INSPECTOR FINDINGS (CORRECT)
# =============================
# This matches Inspector Console -> Findings -> By instance

cve_data = defaultdict(lambda: {"Critical": 0, "High": 0, "All": 0})

for instance_id in instances.keys():
    paginator = inspector.get_paginator("list_findings")

    for page in paginator.paginate(
        filterCriteria={
            "resourceId": [
                {"comparison": "EQUALS", "value": instance_id}
            ],
            "findingType": [
                {"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}
            ],
            "findingStatus": [
                {"comparison": "EQUALS", "value": "ACTIVE"}
            ],
        }
    ):
        for finding in page["findings"]:
            severity = finding["severity"]

            cve_data[instance_id]["All"] += 1

            if severity == "CRITICAL":
                cve_data[instance_id]["Critical"] += 1
            elif severity == "HIGH":
                cve_data[instance_id]["High"] += 1

# =============================
# FINAL REPORT
# =============================
rows = []

for instance_id, inst in instances.items():
    alarms = alarm_map.get(instance_id, [])

    row = {
        "AccountId": ACCOUNT_ID,
        "InstanceId": instance_id,
        "InstanceName": inst["InstanceName"],
        "BackupEnabled": "Yes" if instance_id in protected_instances else "No",
        "MonitoringEnabled": "Yes" if alarms else "No",
        "StateAlarm": "Yes" if any("state" in a or "status" in a for a in alarms) else "No",
        "CPUAlarm": "Yes" if any("cpu" in a for a in alarms) else "No",
        "MemoryAlarm": "Yes" if any("memory" in a for a in alarms) else "No",
        "DiskAlarm": "Yes" if any("disk" in a or "filesystem" in a for a in alarms) else "No",
        "MonitoringAlertLastWeek": "Yes" if alarm_triggered_last_week.get(instance_id) else "No",
        "CVE_Critical": cve_data[instance_id]["Critical"],
        "CVE_High": cve_data[instance_id]["High"],
        "CVE_All": cve_data[instance_id]["All"],
    }

    rows.append(row)

df = pd.DataFrame(rows)
df.to_csv("weekly_ec2_security_report.csv", index=False)

print("Report generated: weekly_ec2_security_report.csv")
