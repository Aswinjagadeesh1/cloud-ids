"""
ingestion/parser.py
Reads simulated AWS CloudTrail JSON logs and normalises each entry
into a standard dict: timestamp, source_ip, user, action, status, resource.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_cloudtrail(path: str | Path) -> list[dict]:
    """Load and normalise all records from a CloudTrail JSON file."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)

    if isinstance(raw, dict):
        # Real CloudTrail exports wrap records under "Records"
        records = raw.get("Records", [])
    elif isinstance(raw, list):
        records = raw
    else:
        raise ValueError(f"Unexpected JSON shape in {path}")

    return [_normalise_cloudtrail(r) for r in records]


def load_auth_log(path: str | Path) -> list[dict]:
    """
    Parse a Linux /var/log/auth.log style file.
    Expected line format (syslog):
      Mar 15 09:05:33 hostname sshd[1234]: Accepted password for alice from 10.0.1.10 port 22 ssh2
    """
    path = Path(path)
    normalised: list[dict] = []
    _YEAR = datetime.now().year

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = _parse_auth_line(line.rstrip(), _YEAR)
            if entry:
                normalised.append(entry)
    return normalised


def load_all_logs(log_dir: str | Path) -> list[dict]:
    """Discover and load every supported log file under *log_dir*."""
    log_dir = Path(log_dir)
    all_logs: list[dict] = []

    for filepath in sorted(log_dir.rglob("*")):
        if not filepath.is_file():
            continue
        suffix = filepath.suffix.lower()
        name   = filepath.name.lower()
        try:
            if suffix == ".json":
                all_logs.extend(load_cloudtrail(filepath))
            elif "auth" in name and suffix in ("", ".log"):
                all_logs.extend(load_auth_log(filepath))
        except Exception as exc:  # noqa: BLE001
            print(f"[parser] Skipping {filepath}: {exc}")

    return all_logs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_cloudtrail(record: dict[str, Any]) -> dict:
    """Map a raw CloudTrail record to the standard schema."""
    user_identity = record.get("userIdentity") or {}
    user = (
        user_identity.get("userName")
        or user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
        or user_identity.get("type", "unknown")
    )

    resources = record.get("resources") or []
    resource = resources[0].get("ARN", "unknown") if resources else "unknown"

    response = record.get("responseElements") or {}
    # Derive status: FAILED if errorCode present or responseElements says FAILED
    error_code = record.get("errorCode") or record.get("errorMessage")
    status = "FAILED" if error_code else (response.get("status", "SUCCESS"))

    return {
        "timestamp":  _parse_ts(record.get("eventTime", "")),
        "source_ip":  record.get("sourceIPAddress", "unknown"),
        "user":       str(user),
        "action":     record.get("eventName", "unknown"),
        "status":     str(status).upper(),
        "resource":   resource,
        # Carry anomaly metadata when present (generated logs include it)
        "_anomaly":   record.get("anomaly", False),
        "_anomaly_type": record.get("anomaly_type"),
        "_raw":       record,
    }


# Syslog auth line pattern
_AUTH_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+\S+:\s+(?P<msg>.+)"
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1
)}


def _parse_auth_line(line: str, year: int) -> dict | None:
    m = _AUTH_RE.match(line)
    if not m:
        return None

    month = _MONTHS.get(m.group("month"), 1)
    day   = int(m.group("day"))
    h, mi, s = (int(x) for x in m.group("time").split(":"))
    ts = datetime(year, month, day, h, mi, s)
    msg = m.group("msg")

    # Determine action / user / ip / status from message text
    if "Accepted" in msg or "Disconnected" in msg:
        action, status = "ssh:Login", "SUCCESS"
    elif "Failed" in msg or "Invalid" in msg:
        action, status = "ssh:Login", "FAILED"
    elif "sudo" in msg.lower():
        action, status = "sudo:Exec", "SUCCESS"
    else:
        action, status = "auth:Event", "SUCCESS"

    user_m = re.search(r"(?:for|user)\s+(\S+)", msg)
    ip_m   = re.search(r"from\s+([\d.]+)", msg)

    return {
        "timestamp":  ts,
        "source_ip":  ip_m.group(1) if ip_m else "unknown",
        "user":       user_m.group(1) if user_m else "unknown",
        "action":     action,
        "status":     status,
        "resource":   "linux:auth",
        "_anomaly":   False,
        "_anomaly_type": None,
        "_raw":       {"raw_line": line},
    }


def _parse_ts(ts_str: str) -> datetime:
    """Parse ISO-8601 timestamp, fall back to now on error."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            pass
    return datetime.utcnow()
