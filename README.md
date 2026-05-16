# AI-Powered Job Fraud Detection & OSINT Intelligence Platform

FraudLens AI is a three-service fraud intelligence platform for fake job posts, fraudulent offer letters, recruitment emails, suspicious terms, and company-related risk signals.

## Services

- `model/`: FastAPI + PyTorch-compatible inference service exposing `POST /predict`.
- `backend/`: FastAPI async API for uploads, analysis, OSINT enrichment, analytics, rate limiting, and graph generation.
- `frontend/`: React + Vite single-page UI with upload/text analysis, D3 graph mapping, OSINT cards, and analytics charts.

## Run With Docker

```bash
docker compose up --build
```

Then open:

- Frontend: `http://localhost:5173`
- Backend health: `http://localhost:8000/health`
- Model health: `http://localhost:8001/health`

## Local Development

Model:

```bash
cd model
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

Backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Key Features

- PDF-to-base64 model inference path through `POST /upload`.
- Fraud, legitimacy, ML, rule, confidence, risk-level, suspicious-term, and legitimate-indicator fields.
- Automatic OSINT trigger when fraud score reaches `FRAUD_OSINT_THRESHOLD`.
- Manual OSINT scan from pasted company, HR email, recruiter, domain, phone, job role, or social-link text.
- DuckDuckGo instant answers, DuckDuckGo HTML search, Reddit JSON, YouTube public search parsing, LinkedIn public-result discovery, GDELT news/blogs, Hacker News, GitHub, scam-report/review-site searches, and company website intelligence collection.
- Concurrent async OSINT execution with timeout fallback.
- Domain-age, scam-report, free-email, and suspicious-TLD risk escalation.
- Entity extraction for emails, phones, domains, URLs, recruiter names, positions, and companies.
- Async-safe analytics using `asyncio.Lock`, UTC timestamps, recent detection history, daily/monthly/yearly counters, and fraud/safe classification.
- In-memory relationship graph generation integrated with analysis results.
- Rate limiting, secure headers, CORS control, MIME validation, PDF signature validation, text size enforcement, sanitization, retries, and model-service circuit breaker.

LinkedIn is handled through public search-result discovery links and snippets. The platform does not attempt to bypass login walls or protected pages.

## Environment Variables

Frontend:

```env
VITE_BACKEND_URL=http://localhost:8000
VITE_ANALYTICS_URL=http://localhost:8000/analytics
```

Backend:

```env
MODEL_SERVICE_URL=http://localhost:8001
REDIS_URL=
RATE_LIMIT=60/minute
SCRAPE_TIMEOUT=18
ALLOWED_ORIGINS=*
FRAUD_OSINT_THRESHOLD=10
```

Model:

```env
MODEL_PATH=models/job_fraud_model.pt
MAX_FILE_SIZE=10485760
INFERENCE_TIMEOUT=20
```

## Training

Add `model/datasets/training.csv` with `text,label` rows and run:

```bash
cd model
python training/train.py
```

The exported checkpoint is `model/models/job_fraud_model.pt`. The model service runs without the checkpoint by using the built-in explainable rules fallback.
