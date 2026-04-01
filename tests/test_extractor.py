"""
Unit tests for the feature extractor.
"""
import pytest
import numpy as np
from datetime import datetime
from features.extractor import extract_features, FEATURE_NAMES

def test_extract_features_empty():
    """Test feature extractor behaves gracefully with empty lists."""
    X, enriched = extract_features([])
    assert X.shape == (0, len(FEATURE_NAMES))
    assert enriched == []

def test_extract_features_valid():
    """Test that feature extraction converts dicts to standard matrices."""
    logs = [
        {
            "timestamp": datetime.now(),
            "source_ip": "1.2.3.4",
            "user": "alice",
            "action": "ConsoleLogin",
            "status": "SUCCESS"
        },
        {
            "timestamp": datetime.now(),
            "source_ip": "1.2.3.5",
            "user": "bob",
            "action": "DeleteVpc",
            "status": "FAILED"
        }
    ]
    X, enriched = extract_features(logs)
    
    assert X.shape[0] == 2
    assert X.shape[1] == len(FEATURE_NAMES)
    assert len(enriched) == 2
    
    # Verify the features match the transformed matrix
    assert "features" in enriched[0]
    assert "failed_login_count" in enriched[0]["features"]

def test_extract_features_missing_keys():
    """Test extractor fills defaults gracefully when keys miss."""
    logs = [
        {
            "timestamp": datetime.now(),
            # Missing fields
        }
    ]
    X, enriched = extract_features(logs)
    assert X.shape == (1, len(FEATURE_NAMES))
    assert enriched[0]["features"]["failed_login_count"] == 0.0
