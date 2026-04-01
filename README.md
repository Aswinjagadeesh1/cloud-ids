<div align="center">

```text
    ____  __                  __   ____  ____  _____
   / __ \/ /___  __  ______  / /  /  _/ / __ \/ ___/
  / / / / / __ \/ / / / __ \/ /   / /  / / / /\__ \ 
 / /_/ / / /_/ / /_/ / /_/ / /___/ /  / /_/ /___/ / 
 \____/_/\____/\__,_/\____/_____/___//_____//____/  
```

**AI-Enhanced Cloud Intrusion Detection System**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?logo=fastapi)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-%23F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![React](https://img.shields.io/badge/React-%2320232a.svg?logo=react&logoColor=%2361DAFB)](https://reactjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An advanced real-time Security Operations Center (SOC) dashboard and pipeline detecting anomalies across unstructured cloud logs using Isolation Forest Machine Learning and Claude AI threat analysis.

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Screenshots](#screenshots)

</div>

<br />

## 📖 Project Overview
Modern log generation scales exponentially, making manual threat-hunting an impossible task. Cloud IDS solves this by systematically applying robust, unsupervised machine learning directly to raw CloudTrail and syslog telemetry. When threats bypass standard threshold alarms, the Isolation Forest model secures anomalous clusters and forwards them straight to an intelligent LLM layer for translation and remediation context.

## ✨ Features
- [x] **Unsupervised Machine Learning**: Deploy `scikit-learn`'s Isolation Forest algorithm to detect zero-day event sequences without required labelling.
- [x] **Automated LLM Threat Analysis**: Contextual, zero-shot inference using the Claude AI API to turn raw `.json` arrays into human-readable mitigation strategies.
- [x] **Real-Time UI Dashboard**: A responsive, auto-refreshing React Security Operations dashboard.
- [x] **Analytics & Statistics**: Visual severity trend charting mapping system alerts dynamically.
- [x] **Pagination & Search**: High-performance backend routing managing heavy telemetry lists, paired with deep client search/filtration queries.
- [x] **Data Exfiltration**: Download active alert tables natively to CSV datasets for compliance and sharing.

## 🛠 Tech Stack

| Component | Framework / Library | Purpose |
| :--- | :--- | :--- |
| **Backend Layer** | FastAPI, Uvicorn | High-performance async REST API endpoints |
| **ML Engine** | `scikit-learn`, NumPy | Isolation Forest anomaly detection execution |
| **Intelligence** | Anthropic Claude API | Advanced, contextual threat evaluation |
| **Frontend UI** | React 18 (Babel) | Interactive, dynamic alert data presentation |
| **Testing** | `pytest` | Robust pipeline configuration validation |

## 📐 Pipeline Architecture

```text
    [ RAW LOG FILES ] 
           │
           ▼
    +--------------------------------+
    | INGESTION (ingestion/parser.py)|
    | Parses CloudTrail & Auth Logs  |
    +--------------------------------+
           │
           ▼
    +--------------------------------+
    | ML MODEL (detection/anomaly.py)|
    | Min-Max Nomralization matrix & |
    | Isolation Forest scoring.      |
    +--------------------------------+
           │
           ▼  (Flags < Threshold)
    +--------------------------------+
    | LLM ANALYZER (claude_analysis) |
    | Context generation & Severity  |
    | remediation routing.           |
    +--------------------------------+
           │
           ▼
    +--------------------------------+
    | FRONTEND (FastAPI / React)     |
    | Live-Refresh Dashboard with    |
    | SVG Charts & Data Search.      |
    +--------------------------------+
```

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/cloud-ids.git
   cd cloud-ids
   ```

2. **Setup your secure Python Environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate    # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure the Environment variables**
   Rename `.env.example` to `.env` and fill in your Anthropic Key.
   ```env
   ANTHROPIC_API_KEY=sk-ant-api03...
   ```

## 💻 Usage

1. **Generate Demo Telemetry**
   Simulate a live data pipeline by injecting unstructured datasets:
   ```bash
   python generate_logs.py
   ```

2. **Start the Engine**
   Initialize the underlying FastAPI backend and React distribution.
   ```bash
   python api/main.py
   ```

3. **Open the Dashboard**
   Navigate to [http://localhost:8000/app](http://localhost:8000/app).
   - *Click "⚡ Run Ingestion"* to trigger an immediate log parsing pipeline cycle.
   - *Click "📥 Export CSV"* to archive present threats.

## 📷 Screenshots

> *(UI Screenshots will be attached here upon project launch)*

- **Live Analytics View**: ![UI Demo Placeholder](https://via.placeholder.com/800x400?text=Live+Dashboard+View)
- **Collapsible Insight View**: ![UI Trace Placeholder](https://via.placeholder.com/800x400?text=Exploratory+Insight+View)

## 🤝 Contributing
Refer to `CONTRIBUTING.md` before making pull requests. We welcome feature additions and architectural improvements.

## ⚖️ License
This project is licensed under the MIT License - see the `LICENSE` file for details.
