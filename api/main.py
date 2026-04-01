"""
api/main.py
FastAPI backend for the Cloud IDS system.

Endpoints
---------
GET  /health   – system health status
GET  /alerts   – paginated alerts 
POST /ingest   – trigger a new ingestion + analysis cycle
GET  /stats    – totals: logs processed, alerts raised, severity breakdown
"""
from __future__ import annotations

import logging
import sys
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

# Make project root importable regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ingestion.parser     import load_cloudtrail, load_all_logs
from detection.anomaly    import detect_anomalies, score_all, get_last_model_stats
from claude_analysis.analyser import analyse_batch

# ---------------------------------------------------------------------------
# Setup Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("api")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title       = "Cloud IDS API",
    description = "AI-Enhanced Cloud Intrusion Detection System",
    version     = "1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with method, path, status code, and timing."""
    start_time = time.time()
    try:
        response = await call_next(request)
        status_code = response.status_code
    except Exception as exc:
        status_code = 500
        raise exc
    finally:
        process_time = time.time() - start_time
        logger.info(f"{request.method} {request.url.path} - {status_code} - {process_time:.4f}s")
    return response

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Return a structured JSON message for any unhandled exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "message": str(exc)},
    )

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

_store: dict[str, Any] = {
    "alerts":          [],          # list of alert dicts
    "total_logs":      0,
    "total_alerts":    0,
    "severity_counts": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
    "last_ingest":     None,
    "uptime_start":    datetime.utcnow().isoformat(),
    "total_runs":      0,
    "model_status":    "Ready"
}

LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialise_entry(entry: dict) -> dict:
    """Turn a log entry into a JSON-safe dict."""
    out = {}
    for k, v in entry.items():
        if k.startswith("_"):          # skip internal fields
            continue
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        elif isinstance(v, float):
            out[k] = round(v, 6)
        else:
            out[k] = v
    return out

def _run_pipeline() -> dict:
    """Full ingest → detect → analyse cycle. Returns summary."""
    try:
        _store["model_status"] = "Processing logs"
        
        # 1. Load logs
        logs = load_all_logs(LOGS_DIR)
        if not logs:
            raise HTTPException(status_code=404, detail="No log files found in logs/ directory.")

        _store["model_status"] = "Detecting anomalies"
        
        # 2. Detect anomalies
        flagged = detect_anomalies(logs)

        _store["model_status"] = "Analysing threats"

        # 3. Rule-based / LLM analysis
        analyses = analyse_batch(flagged)

        # 4. Build alert objects
        new_alerts: list[dict] = []
        sev_counts: dict[str, int] = defaultdict(int)

        run_id = str(uuid.uuid4())
        _store["total_runs"] += 1

        for entry, analysis in zip(flagged, analyses):
            alert = {
                **_serialise_entry(entry),
                "explanation":    analysis["explanation"],
                "severity":       analysis["severity"],
                "recommendation": analysis["recommendation"],
                "confidence_percentage": entry.get("confidence_percentage", 0.0),
                "ingested_at":    datetime.utcnow().isoformat(),
                "run_id":         run_id
            }
            new_alerts.append(alert)
            sev_counts[analysis["severity"]] += 1

        # 5. Update in-memory store
        _store["alerts"].extend(new_alerts)
        _store["alerts"] = _store["alerts"][-2000:]   # increase hard cap
        _store["total_logs"]   += len(logs)
        _store["total_alerts"] += len(new_alerts)
        for sev, cnt in sev_counts.items():
            _store["severity_counts"][sev] = _store["severity_counts"].get(sev, 0) + cnt
        _store["last_ingest"] = datetime.utcnow().isoformat()
    
    except Exception as e:
        _store["model_status"] = "Failed"
        raise e
    finally:
        if _store["model_status"] != "Failed":
             _store["model_status"] = "Ready"

    return {
        "logs_processed": len(logs),
        "alerts_raised":  len(new_alerts),
        "severity_breakdown": dict(sev_counts),
        "run_id": run_id
    }

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

class IngestResponse(BaseModel):
    message:            str
    logs_processed:     int
    alerts_raised:      int
    severity_breakdown: dict
    run_id:             str

@app.get("/health")
def health_check():
    """Return system health details and ML model status."""
    return {
        "status":       "ok",
        "uptime_start": _store["uptime_start"],
        "last_ingest":  _store["last_ingest"],
        "total_runs":   _store["total_runs"],
        "model_status": _store["model_status"]
    }

@app.get("/alerts")
def get_alerts(page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100)):
    """Return the paginated analysed alerts (newest first)."""
    try:
        alerts = list(reversed(_store["alerts"]))
        start = (page - 1) * limit
        end = start + limit
        paginated = alerts[start:end]
        return {
            "alerts": paginated,
            "count": len(paginated),
            "total": len(alerts),
            "page": page,
            "limit": limit
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pagination error: {str(exc)}")

@app.post("/ingest", response_model=IngestResponse)
def ingest():
    """Trigger a full ingestion and analysis cycle."""
    result = _run_pipeline()
    return IngestResponse(
        message            = "Ingestion complete.",
        logs_processed     = result["logs_processed"],
        alerts_raised      = result["alerts_raised"],
        severity_breakdown = result["severity_breakdown"],
        run_id             = result["run_id"]
    )

@app.get("/stats")
def get_stats():
    """Return aggregate statistics."""
    try:
        return {
            "total_logs_processed": _store["total_logs"],
            "total_alerts":         _store["total_alerts"],
            "severity_counts":      _store["severity_counts"],
            "last_ingest":          _store["last_ingest"],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/model-stats")
def model_stats():
    """Return feature importance weights, anomalies detected, and score distribution."""
    try:
        return get_last_model_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/")
def root():
    return {"status": "ok", "service": "Cloud IDS API v1.0.0"}

# ---------------------------------------------------------------------------
# Frontend Mount
# ---------------------------------------------------------------------------
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
