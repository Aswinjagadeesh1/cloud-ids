"""
features/extractor.py
Extracts a numeric feature vector from a list of normalised log entries
so the ML model can score each event.

Features per entry
------------------
failed_login_count   : count of FAILED events by same user in the same hour window
unique_ip_count      : number of distinct IPs seen for this user across all logs
off_hours_activity   : 1 if event is outside 09:00–18:00, else 0
privilege_escalation : 1 if action suggests privilege escalation, else 0
data_volume_mb       : estimated data transferred in MB (parsed from raw record)
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

import numpy as np

# Actions that indicate privilege escalation
_PRIV_ESC_ACTIONS = frozenset({
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreateUser",
    "iam:AddUserToGroup",
    "iam:AttachGroupPolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sudo:Exec",
})

FEATURE_NAMES = [
    "failed_login_count",
    "unique_ip_count",
    "off_hours_activity",
    "privilege_escalation",
    "data_volume_mb",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(logs: list[dict]) -> tuple[np.ndarray, list[dict]]:
    """
    Given normalised log entries, return:
      - X  : np.ndarray of shape (N, len(FEATURE_NAMES))
      - enriched_logs : each log dict annotated with its feature vector
    """
    # --- Pre-compute per-user aggregates across entire log set ---
    user_ips: dict[str, set] = defaultdict(set)
    # (user, hour_bucket) -> failed count
    user_hour_fails: dict[tuple[str, str], int] = defaultdict(int)

    for entry in logs:
        user = entry["user"]
        ip   = entry["source_ip"]
        ts: datetime = entry["timestamp"]
        hour_bucket = ts.strftime("%Y-%m-%d-%H")

        user_ips[user].add(ip)
        if entry["status"] == "FAILED":
            user_hour_fails[(user, hour_bucket)] += 1

    rows: list[list[float]] = []
    enriched: list[dict] = []

    for entry in logs:
        user   = entry["user"]
        ts: datetime = entry["timestamp"]
        hour_bucket  = ts.strftime("%Y-%m-%d-%H")

        failed_count  = float(user_hour_fails.get((user, hour_bucket), 0))
        unique_ips    = float(len(user_ips.get(user, set())))
        off_hours     = 1.0 if (ts.hour < 9 or ts.hour >= 18) else 0.0
        priv_esc      = 1.0 if entry["action"] in _PRIV_ESC_ACTIONS else 0.0
        data_vol      = _extract_data_volume(entry.get("_raw") or {})

        feature_vec = [failed_count, unique_ips, off_hours, priv_esc, data_vol]
        rows.append(feature_vec)

        enriched_entry = dict(entry)
        enriched_entry["features"] = dict(zip(FEATURE_NAMES, feature_vec))
        enriched.append(enriched_entry)

    X = np.array(rows, dtype=float)
    return X, enriched


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_data_volume(raw: dict[str, Any]) -> float:
    """Attempt to parse a transferred-bytes figure from the raw record."""
    # Generated anomaly records include bytesTransferredOut directly
    bytes_out = raw.get("bytesTransferredOut")
    if bytes_out is not None:
        try:
            return float(bytes_out) / 1_000_000
        except (TypeError, ValueError):
            pass

    # Real CloudTrail additionalEventData
    additional = raw.get("additionalEventData") or {}
    for key in ("bytesTransferredIn", "bytesTransferredOut", "objectSize"):
        val = additional.get(key)
        if val is not None:
            try:
                return float(val) / 1_000_000
            except (TypeError, ValueError):
                pass

    return 0.0
