"""In-process latency benchmark (TestClient, SQLite, single process). NOT a production load test: see locustfile.py for that."""
import sys, os, time, statistics; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ["DATABASE_URL"] = "sqlite:////tmp/bench.db"
from fastapi.testclient import TestClient
from app.main import app
from app import security
c = TestClient(app); c.post("/auth/register", json={"email": "b@x.com", "password": "correct-horse-1"}); c.headers["x-csrf-token"] = c.cookies["csrf"]
for i in range(50): c.post("/tasks", json={"title": f"t{i}"})
for name, fn in (("GET /health", lambda: c.get("/health")), ("GET /tasks (50 rows)", lambda: c.get("/tasks")), ("POST /ask", lambda: c.post("/ask", json={"question": "tasks"}))):
    ts = []
    for _ in range(200): security._hits.clear(); t = time.perf_counter(); r = fn(); ts.append((time.perf_counter() - t) * 1000); assert r.status_code == 200
    ts.sort(); print(f"{name:22} p50={statistics.median(ts):.1f}ms p95={ts[int(.95*len(ts))]:.1f}ms n=200")
