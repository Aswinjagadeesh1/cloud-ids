"""
claude_analysis/analyser.py

Rule-based threat analyser with no external API needed for strict portfolio implementation.
Returns a structured threat analysis dict based on defined rules:
  {
    "explanation":     str,   # 2-sentence plain-English summary
    "severity":        str,   # Low | Medium | High | Critical
    "recommendation":  str,   # one immediate action
  }
"""
from __future__ import annotations
from typing import Dict

def analyse_event(flagged_entry: dict) -> dict:
    """
    Analyse a single flagged log entry based on predefined threat-hunting heuristic rules.
    
    This function acts as a rules-based expert system, evaluating extracted features 
    such as off-hours activity, failed logins, and privilege escalation flags to 
    determine the severity and recommend appropriate remediation responses, mimicking 
    SOC analyst thought processes.
    
    Args:
        flagged_entry (dict): A dictionary representing the anomalous log event,
                              including its features and computed anomaly score.
                              
    Returns:
        dict: A structured analysis containing three keys:
            - explanation (str): Plain-English description of what happened.
            - severity (str): 'Critical', 'High', 'Medium', or 'Low'.
            - recommendation (str): Immediate mitigation action for the SOC.
    """
    action: str = flagged_entry.get("action", "").lower()
    user: str = flagged_entry.get("user", "")
    source_ip: str = flagged_entry.get("source_ip", "")
    anomaly_score: float = float(flagged_entry.get("anomaly_score", 0.0))
    features: dict = flagged_entry.get("features", {})
    
    # Extract calculated features from features/extractor.py matrix
    failed_logins: float = float(features.get("failed_login_count", 0.0))
    is_off_hours: bool = float(features.get("off_hours_activity", 0.0)) > 0
    is_priv_esc_feat: bool = float(features.get("privilege_escalation", 0.0)) > 0
    unique_ips: float = float(features.get("unique_ip_count", 0.0))

    # -------------------------------------------------------------------------
    # Rules Engine
    # -------------------------------------------------------------------------
    # The engine evaluates cases sequentially in order of priority (most destructive first).
    # It returns immediately upon hitting a matching case to guarantee high-risk activities
    # like data destruction overrule low-level anomalies.

    # Priority 1: Mass S3 Bucket / Object Destructive behavior
    if "deletebucket" in action or "deleteobject" in action:
        # Scale severity based on ML confidence score
        severity: str = "Critical" if anomaly_score < -0.2 else "High"
        return {
            "explanation": f"High volume of deletion actions ('{flagged_entry.get('action')}') detected from user '{user}'. This could indicate a malicious insider or compromised account attempting to destroy data.",
            "severity": severity,
            "recommendation": "Immediately restrict the user's delete permissions and review recent access logs."
        }
        
    # Priority 2: Privilege Escalation Attempts (IAM changes)
    if is_priv_esc_feat or "policy" in action or "attach" in action or "role" in action:
        severity = "Critical" if anomaly_score < -0.2 else "High"
        return {
            "explanation": f"Potential privilege escalation attempt by user '{user}'. The action '{flagged_entry.get('action')}' modifies access controls, which may grant unauthorized elevated permissions.",
            "severity": severity,
            "recommendation": "Validate the IAM changes and revert any unauthorized policy modifications immediately."
        }
        
    # Priority 3: Abnormal Root Account Usage
    if user.lower() == "root" and is_off_hours and "login" in action:
        return {
            "explanation": f"Root login detected during off-hours from IP {source_ip}. Root account usage should be rare and is highly suspicious outside normal business hours.",
            "severity": "Critical",
            "recommendation": "Verify the identity of the person using the root account and enforce MFA if not already enabled."
        }
        
    # Priority 4: Impossible Travel / Geographic Dispersity / Botnet (many random IPs)
    if unique_ips > 3 or (anomaly_score < -0.2 and "login" in action):
        return {
            "explanation": f"Activity from an unusual number of distinct IP addresses ({int(unique_ips)}) or anomalous IP origin ({source_ip}) for user '{user}'. This suggests possible credential compromise.",
            "severity": "High",
            "recommendation": "Force a password reset for the user and block suspicious IP addresses."
        }
        
    # Priority 5: Credential Stuffing / Brute Force
    if failed_logins > 5:
        return {
            "explanation": f"Multiple failed login attempts ({int(failed_logins)}) detected for user '{user}'. This often indicates a brute-force or credential stuffing attack.",
            "severity": "Medium",
            "recommendation": "Review login logs, block the offending IP address, and ensure account lockout policies are active."
        }
        
    # Priority 6: Generic Statistical Anomaly (Fallback)
    # Applied when Isolation Forest caught an anomaly but no specific rule matched.
    severity = "High" if anomaly_score < -0.25 else "Medium"
    return {
        "explanation": f"Anomalous activity detected for user '{user}' performing action '{flagged_entry.get('action')}' with an anomaly score of {anomaly_score:.2f}. The behavior deviates from established baselines.",
        "severity": severity,
        "recommendation": "Investigate the event context in the SIEM to determine if the activity was authorized."
    }

def analyse_batch(flagged_entries: list[dict]) -> list[dict]:
    """
    Analyse a batch of flagged anomalous events, routing them sequentially to the rules engine.
    
    Args:
        flagged_entries (list[dict]): The array of anomalous events from IsolationForest.
        
    Returns:
        list[dict]: Explanations, severity, and recommendations tightly paired to each entry.
    """
    return [analyse_event(e) for e in flagged_entries]
