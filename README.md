# LifeMesh backend (v0.1, core slice)

FastAPI + SQLAlchemy modular monolith. Runs locally with SQLite and no credentials; Docker Compose uses Postgres (pgvector image), Redis and Celery.

## Run
    cp .env.example .env        # set SECRET_KEY and TOKEN_KEY
    docker compose up --build   # API on :8000, docs at /docs
    # or without Docker:  pip install -r requirements.txt && uvicorn app.main:app --reload
    python -m pytest -q         # 10 tests

## Google OAuth setup (required for real Gmail/Calendar)
1. Google Cloud Console: create a project, enable **Gmail API** and **Google Calendar API**.
2. OAuth consent screen: add yourself as a **test user** (Gmail scopes are *restricted*; public launch needs Google verification).
3. Create an OAuth client (Web). Redirect URI: `http://localhost:8000/integrations/google/callback`.
4. Put the client ID/secret in `.env`. Scopes requested (read-only): `openid email gmail.readonly calendar.readonly`.
Without these, `/integrations/google/connect` returns 503 and nothing is shown as connected.

## Run
    cp .env.example .env && docker compose up --build      # UI + API on http://localhost:8000, API docs at /docs
    alembic upgrade head                                    # production schema (AUTO_CREATE=0); dev auto-creates tables
    python -m pytest -q                                     # 19 tests
    python tests/e2e_browser.py                             # real Chromium test (needs: playwright install chromium)
    python eval/run_eval.py ; python eval/bench.py          # measured evaluations / in-process latency
    locust -f locustfile.py --host http://localhost:8000    # real load test against a running stack

## Verified (automated)
Auth/CSRF/rate limit, per-user isolation, versioned facts + change detection, explainable risk rules, IsolationForest anomaly
model, conflicts, briefing, Ask (cited, injection-safe), upload limits, Alembic migration, webhooks (simulated payloads),
Google OAuth/sync/refresh/revoke/410/404 handling (against SIMULATED Google responses), UI flow in real Chromium.

## Measured (small synthetic sets written by the developer, so optimistic; not real-world accuracy)
extraction P/R 1.00/1.00 (9 items) | risk rules: 3/3 risky caught, 0/6 benign flagged | anomaly model: 7 of 10 injected in top-10
in-process latency (SQLite, 1 process): /health p50 2.0 ms, /tasks p50 3.5 ms, /ask p50 3.7 ms

## NOT verified against real services (needs your credentials)
Real Google/Microsoft OAuth, Gmail/Calendar sync, Pub/Sub + Calendar watch + Graph subscriptions, tesseract OCR on real images,
OTLP export, Postgres under Docker Compose. Expect first-run fixes.

## Known limitations
Search embeddings are local hashed n-grams (lexical, no synonyms); pgvector is not used. Ask is extractive, no LLM.
Extraction is English regex; entity linking keys on normalized subject. No write scopes: LifeMesh cannot send mail or edit events.
Microsoft calendar sync, retention scheduler, notification delivery, analytics charts and a design-system UI are not built.
UI is a compact vanilla-JS app, not the animated Next.js landing page (that remains the separate published demo).
