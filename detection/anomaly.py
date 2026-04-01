"""
detection/anomaly.py

This module contains the Isolation Forest machine learning pipeline for detecting
anomalies in access logs. It applies scikit-learn's IsolationForest to the features
extracted from the raw logs.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import TypedDict, Any

from features.extractor import extract_features, FEATURE_NAMES

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANOMALY_THRESHOLD = -0.1   # score below this -> suspicious
IF_PARAMS = {
    "n_estimators":   200,
    "contamination":  0.08,   # Expect ~8% of the data to be anomalous
    "random_state":   42,
    "max_samples":    "auto",
}

# ---------------------------------------------------------------------------
# Global State for Model Stats
# ---------------------------------------------------------------------------
# Holds the latest run's distribution and stats
_LAST_MODEL_STATS: dict[str, Any] = {
    "feature_importance": {},
    "score_distribution": {"bins": [], "counts": []},
    "total_detected": 0
}

def get_last_model_stats() -> dict[str, Any]:
    """Retrieve the stored model statistics from the last detection run."""
    return _LAST_MODEL_STATS

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_anomalies(logs: list[dict]) -> list[dict]:
    """
    Run Isolation Forest over unstructured logs and filter out the benign logs.
    
    The function performs feature extraction, model fitting, and scoring.
    It applies a min-max normalisation algorithm to securely convert raw IF decision 
    scores into a human-readable confidence percentage (0-100%).

    Args:
        logs (list[dict]): A list of normalized log dictionaries.

    Returns:
        list[dict]: A filtered list containing only the logs deemed anomalous
                    (i.e., those with score < ANOMALY_THRESHOLD).
    """
    if not logs:
        return []

    # X is our feature matrix, enriched is a list of dicts with original data + extracted features
    X, enriched = extract_features(logs)

    # Initialize and fit the Scikit-Learn IsolationForest model
    model = IsolationForest(**IF_PARAMS)
    model.fit(X)
    
    # isolation forest paths lengths. The lower the score, the more anomalous the point.
    scores: np.ndarray = model.score_samples(X)

    # -----------------------------------------------------------------------
    # Portfolio Requirement: Min-Max Normalization to 0-100% Confidence Profile
    # -----------------------------------------------------------------------
    if len(scores) > 0:
        min_s = scores.min()
        max_s = scores.max()
        if max_s > min_s:
            # Invert: The lowest score maps to 100% (highest confidence of anomaly)
            confidences = (max_s - scores) / (max_s - min_s) * 100.0
        else:
            confidences = np.zeros_like(scores)
    else:
        confidences = np.array([])
        
    # Generate stats for the model endpoint
    _update_model_stats(X, scores, confidences)

    flagged: list[dict] = []
    
    # Bundle scores and confidences back into the JSON payloads
    for entry, score, conf in zip(enriched, scores, confidences):
        score_f = float(score)
        entry["anomaly_score"] = score_f
        entry["confidence_percentage"] = float(conf)
        entry["is_flagged"] = score_f < ANOMALY_THRESHOLD
        
        if entry["is_flagged"]:
            flagged.append(entry)

    return flagged


def score_all(logs: list[dict]) -> list[dict]:
    """
    Execute anomaly scoring over logs, strictly returning the entirety of 
    scored logs rather than filtering out standard cases. Used primarily for 
    batch analytics or deep inspection tools.

    Args:
        logs (list[dict]): Standard logs dict list.

    Returns:
        list[dict]: The exact same list but mutated to contain scoring keys.
    """
    if not logs:
        return []

    X, enriched = extract_features(logs)

    model = IsolationForest(**IF_PARAMS)
    model.fit(X)
    scores: np.ndarray = model.score_samples(X)

    if len(scores) > 0:
        min_s = scores.min()
        max_s = scores.max()
        confidences = (max_s - scores) / (max_s - min_s) * 100.0 if max_s > min_s else np.zeros_like(scores)
    else:
        confidences = np.array([])

    result: list[dict] = []
    for entry, score, conf in zip(enriched, scores, confidences):
        score_f = float(score)
        entry["anomaly_score"] = score_f
        entry["confidence_percentage"] = float(conf)
        entry["is_flagged"] = score_f < ANOMALY_THRESHOLD
        result.append(entry)

    return result

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _update_model_stats(X: np.ndarray, scores: np.ndarray, confidences: np.ndarray) -> None:
    """
    Calculate and update runtime model analytics internally for API dashboards.
    
    Args:
        X (np.ndarray): The raw feature matrix.
        scores (np.ndarray): The resultant anomaly scores.
        confidences (np.ndarray): The calculated confidence percentages.
    """
    # Simulate feature importance by examining feature standard deviation for flagged anomalies
    flagged_mask = scores < ANOMALY_THRESHOLD
    
    importances = {}
    if np.any(flagged_mask):
        anomalies_X = X[flagged_mask]
        stds = anomalies_X.std(axis=0)
        # Handle zero standard deviations
        stds_sum = stds.sum() if stds.sum() > 0 else 1.0
        weights = stds / stds_sum
        importances = {name: round(float(w), 3) for name, w in zip(FEATURE_NAMES, weights)}
    else:
        importances = {name: 0.0 for name in FEATURE_NAMES}

    # Generate a lightweight distribution
    counts, bin_edges = np.histogram(scores, bins=10)
    
    _LAST_MODEL_STATS["feature_importance"] = importances
    _LAST_MODEL_STATS["score_distribution"] = {
        "bins": [round(float(b), 3) for b in bin_edges[:-1]],
        "counts": [int(c) for c in counts]
    }
    _LAST_MODEL_STATS["total_detected"] = int(flagged_mask.sum())
