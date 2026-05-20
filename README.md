# 🛡️ FraudLens AI — Job Fraud Detection & OSINT Intelligence Platform

> **FraudLens AI** is a production-ready, three-microservice platform that detects fake job postings, fraudulent offer letters, and suspicious recruitment communications using a hybrid AI + OSINT intelligence pipeline.

🔗 **Live Demo:** [ai-fraud-detection-neon.vercel.app](https://ai-fraud-detection-neon.vercel.app)
📦 **Repo:** [github.com/AR-Ballava/AI_FRAUD_DETECTION](https://github.com/AR-Ballava/AI_FRAUD_DETECTION)

---

## 📌 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Model Training](#model-training)
- [Project Structure](#project-structure)
- [Security](#security)
- [Roadmap](#roadmap)

---

## Overview

Every year, millions of job seekers fall victim to fake job postings, phishing offer letters, and fraudulent recruiter emails. Existing rule-based systems fail to adapt to evolving tactics and lack any real-world intelligence enrichment.

**FraudLens AI** solves this by combining:
- A **PyTorch ML inference engine** (with an explainable rule-based fallback)
- An **async OSINT enrichment pipeline** that cross-references 10+ live intelligence sources
- A **React + D3 visual dashboard** showing risk scores, entity relationship graphs, and detection analytics

Users can upload a PDF (offer letter, job posting) or paste raw text and receive a detailed fraud risk report in seconds — complete with suspicious entity extraction, OSINT intelligence cards, and a visual relationship graph.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    User / Browser                    │
│              React + Vite Frontend (5173)            │
│        D3 Graph  │  OSINT Cards  │  Analytics        │
└──────────────────┬──────────────────────────────────┘
                   │ HTTP / REST
┌──────────────────▼──────────────────────────────────┐
│              Backend API (FastAPI :8000)              │
│  Upload  │  OSINT Engine  │  Analytics  │  Graph Gen  │
│  Rate Limiting │ Auth Headers │ Validation │ Retries   │
└──────────────────┬──────────────────────────────────┘
                   │ HTTP (internal)
┌──────────────────▼──────────────────────────────────┐
│            Model Service (FastAPI :8001)              │
│    PyTorch Inference  +  Rule-Based Fallback          │
│            POST /predict                              │
└─────────────────────────────────────────────────────┘
```

All three services are orchestrated via **Docker Compose** with health checks and dependency ordering (`model` → `backend` → `frontend`).

---

## Features

### 🤖 AI Fraud Analysis
- **PDF upload pipeline** — PDF → base64 encoding → model inference via `POST /upload`
- **Text paste analysis** — raw text analyzed directly
- **Hybrid inference** — PyTorch ML model with automatic rule-based fallback if checkpoint is unavailable
- **Rich output fields:** fraud score, legitimacy score, ML confidence, rule-based score, risk level, suspicious terms, and legitimate indicators

### 🔍 OSINT Intelligence Engine
- **Automatic trigger** — OSINT runs automatically when fraud score exceeds `FRAUD_OSINT_THRESHOLD`
- **Manual scan** — paste any company name, HR email, recruiter, domain, phone, job role, or social link
- **10+ intelligence sources queried concurrently:**
  - DuckDuckGo Instant Answers + HTML search
  - Reddit JSON API
  - YouTube public search
  - LinkedIn public result discovery
  - GDELT news and blogs
  - Hacker News
  - GitHub
  - Scam-report and review-site searches
  - Company website intelligence collection
- **Concurrent async execution** with per-source timeout fallback

### 🕵️ Entity Extraction
Automatically extracts and identifies:
- Email addresses (flags free/suspicious providers)
- Phone numbers
- Domains and URLs (checks domain age + TLD risk)
- Recruiter names and positions
- Company names

### 📊 Analytics Dashboard
- Daily, monthly, and yearly detection counters
- Fraud vs. safe classification breakdown
- Recent detection history
- Async-safe updates using `asyncio.Lock` with UTC timestamps

### 🕸️ Relationship Graph
- In-memory entity relationship graph generated per analysis
- Rendered in the frontend using **D3.js** force-directed layout
- Visualizes connections between companies, domains, emails, and recruiters

### 🔒 Security & Reliability
- Rate limiting (configurable, default 60 req/min)
- Secure HTTP headers
- CORS control
- MIME type validation
- PDF magic-byte signature validation
- Text size enforcement and sanitization
- Automatic retries
- **Circuit breaker** for model service (prevents cascade failure)

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, Vite, D3.js, CSS |
| Backend | Python, FastAPI, asyncio, aiohttp |
| Model Service | Python, FastAPI, PyTorch |
| OSINT | aiohttp, DuckDuckGo, GDELT, Reddit, YouTube, GitHub APIs |
| Containerization | Docker, Docker Compose |
| Frontend Deployment | Vercel |
| Model Training | PyTorch, custom training pipeline |

---

## Getting Started

### Prerequisites
- Docker & Docker Compose
- OR: Python 3.10+, Node.js 18+

### Run with Docker (Recommended)

```bash
git clone https://github.com/AR-Ballava/AI_FRAUD_DETECTION.git
cd AI_FRAUD_DETECTION
docker compose up --build
```

Then open:
- **Frontend:** http://localhost:5173
- **Backend health:** http://localhost:8000/health
- **Model health:** http://localhost:8001/health

### Local Development

**Model service:**
```bash
cd model
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

---

## Environment Variables

### Frontend (`frontend/.env`)
```env
VITE_BACKEND_URL=http://localhost:8000
VITE_ANALYTICS_URL=http://localhost:8000/analytics
```

### Backend (`backend/.env`)
```env
MODEL_SERVICE_URL=http://localhost:8001
REDIS_URL=
RATE_LIMIT=60/minute
SCRAPE_TIMEOUT=18
ALLOWED_ORIGINS=*
FRAUD_OSINT_THRESHOLD=10
```

### Model (`model/.env`)
```env
MODEL_PATH=models/job_fraud_model.pt
MAX_FILE_SIZE=10485760
INFERENCE_TIMEOUT=20
```

---

## API Reference

### Backend (`localhost:8000`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `POST` | `/upload` | Upload PDF for fraud analysis |
| `POST` | `/analyze` | Analyze pasted text |
| `POST` | `/osint` | Run OSINT scan on entity text |
| `GET` | `/analytics` | Retrieve detection analytics |

### Model (`localhost:8001`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Model service health check |
| `POST` | `/predict` | Run fraud inference on text/base64 |

---

## Model Training

Add training data to `model/datasets/training.csv` with `text,label` columns, then run:

```bash
cd model
python training/train.py
```

The trained checkpoint is saved at `model/models/job_fraud_model.pt`.

> **Note:** The model service runs without a checkpoint using the built-in explainable rule-based fallback — no training is required to run the platform.

---

## Project Structure

```
AI_FRAUD_DETECTION/
├── model/                    # ML inference microservice (FastAPI :8001)
│   ├── app/
│   │   └── main.py           # FastAPI app with /predict endpoint
│   ├── models/               # Saved PyTorch checkpoints
│   ├── training/             # Training scripts
│   │   └── train.py
│   ├── datasets/             # Training CSV data
│   └── requirements.txt
│
├── backend/                  # Core API microservice (FastAPI :8000)
│   ├── app/
│   │   └── main.py           # FastAPI app: upload, OSINT, analytics, graph
│   └── requirements.txt
│
├── frontend/                 # React SPA (Vite :5173)
│   ├── src/
│   │   └── ...               # Components: upload, OSINT cards, D3 graph, analytics
│   └── package.json
│
├── docker-compose.yml        # Multi-service orchestration
└── README.md
```

---

## Security

- All file uploads are validated via MIME type and PDF magic bytes before processing
- Text inputs are sanitized and size-limited before ML inference
- Rate limiting prevents API abuse
- Secure HTTP headers applied on all responses
- CORS strictly controlled via `ALLOWED_ORIGINS`
- OSINT only uses public-facing data; no login-wall bypass attempted
- LinkedIn handled via public search result snippets only

---

## Roadmap

- [ ] Persistent analytics storage (Redis / PostgreSQL)
- [ ] User accounts and saved scan history
- [ ] Email/webhook alerts when high-risk jobs are detected
- [ ] Browser extension for real-time LinkedIn job scanning
- [ ] Expanded ML dataset and improved model accuracy
- [ ] REST API key system for third-party integrations

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

> Built to protect job seekers from recruitment fraud using the power of AI and open-source intelligence.