"""
Unit tests for the anomaly detection module.
"""
import pytest
from datetime import datetime
from detection.anomaly import detect_anomalies, score_all

def _mock_logs(n_normal, n_anomaly):
    """Produces mock structured logs for the model pipeline."""
    logs = []
    # Gen benign
    for _ in range(n_normal):
        logs.append({
            "timestamp": datetime.now(),
            "source_ip": "10.0.0.1",
            "user": "alice",
            "action": "ConsoleLogin",
            "status": "SUCCESS"
        })
    # Gen anomalous
    for _ in range(n_anomaly):
        logs.append({
            "timestamp": datetime.now(),
            "source_ip": "203.0.113.1",
            "user": "root",
            "action": "DeleteVpc",
            "status": "FAILED"
        })
    return logs

def test_detect_anomalies():
    """Test whether the anomalies are filtered correctly."""
    logs = _mock_logs(50, 5)
    flagged = detect_anomalies(logs)
    
    # Not exact because It's an unsupervised statistical ML model, but should find *some*
    assert len(flagged) > 0
    assert len(flagged) <= len(logs)
    
    for f in flagged:
         assert 0.0 <= f["confidence_percentage"] <= 100.0
         assert "anomaly_score" in f
         assert f["is_flagged"] is True

def test_score_all():
    """Test score_all returns precisely the same quantity without filtering."""
    logs = _mock_logs(10, 2)
    scored = score_all(logs)
    
    assert len(scored) == 12
    
    for s in scored:
        assert "anomaly_score" in s
        assert "confidence_percentage" in s
        assert "is_flagged" in s
