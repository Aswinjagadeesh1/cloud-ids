# Architecture Guide: Cloud Intrusion Detection System

## Overview
The Cloud IDS is an end-to-end framework designed to ingest, process, and automatically analyze cloud server and application logs for malicious behaviour. It solves the critical bottleneck in modern Security Operations Centers (SOCs): alert fatigue. 

By layering an unsupervised machine learning model (Isolation Forest) with a Large Language Model (Claude API), the system accurately detects anomalous events and translates raw security telemetry into actionable, human-readable threat remediation advice.

## Data Flow
The data flow represents a clear, unidirectional pipeline from raw data to visual insight.

```text
[ Raw Logs ] -> (Ingestion & Normalisation) -> [ Feature Matrix ] -> (ML Engine) -> [ Flagged Anomalies ] -> (AI Analysis) -> [ Dashboard UI ]
```

1. **Ingestion (`ingestion/`)**: Parsers scan target paths for `.json` (CloudTrail) or `.log` (Syslog/Auth). Time formats, resources, and endpoints are normalised into a unified schema dictionary.
2. **Extraction (`features/`)**: Normalised dictionaries are extracted into a numerical NumPy feature matrix. Target features include boolean traits, status counts, and action severities mappings.
3. **ML Engine (`detection/`)**: Scikit-Learn's `IsolationForest` processes the batch. Standard events map tightly in higher dimensions, isolating anomalous events on the tree's perimeter. Scores are inverted and min-max normalised into a strict 0-100% confidence percentage profile.
4. **Threat Intelligence (`claude_analysis/`)**: Rather than simply dumping an anomaly flag, flagged entries hit the LLM layer via `analyser.py`. Using zero-shot prompts, Claude identifies lateral movements or evasion techniques and suggests remediation.
5. **Backend & Frontend (`api/` and `frontend/`)**: FastAPI manages the data presentation through heavily paginated, documented endpoints. A real-time React dashboard fetches aggregates, charts, and interactive paginated tables.

## Technology Choices

| Layer | Technology | Reason |
| --- | --- | --- |
| **Backend API** | FastAPI (Python) | High concurrency out-of-the-box, automatic Swagger/OpenAPI docs, and typing-first integration fit perfectly for a data-heavy pipeline. |
| **ML Engine** | `scikit-learn` (Isolation Forest) | Isolation Forest scales exceptionally well on tabular telemetry. It requires no labelled data (unsupervised) making it uniquely suited for zero-day variance. |
| **Intelligence** | Anthropic Claude Sonnet | Leading-edge contextual reasoning suitable for evaluating obscure command chains and producing strict JSON. |
| **Frontend UI** | React 18, Babel | Chosen for modular DOM updates required for live-refresh SOC dashboards. Served locally via FastAPI removing external pipeline builds. |

## Security Considerations
- **Data Privacy**: No raw PII logs are persisted externally. LLM prompts strip sensitive network maps where necessary, keeping logic inside the API perimeter.
- **Dependency Isolation**: All local runs use an isolated Virtual Environment (`.venv`) ensuring no system library collisions occur for reproducibility.
- **Model Poisoning Mitigation**: The `generate_logs.py` script strictly guarantees fresh anomalous telemetry per cycle ensuring the demo retains pristine Isolation Forest distribution curves.
