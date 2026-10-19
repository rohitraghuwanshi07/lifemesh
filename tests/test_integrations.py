"""OAuth/sync/webhook/ML tests run against SIMULATED Google/Microsoft responses (monkeypatched HTTP). They prove our logic, not Google's behavior."""
import base64, json, urllib.parse
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from fastapi.testclient import TestClient
from test_core import mk_client
from app.main import app
from app import google, webhooks, models, ml
from app.config import settings
from app.db import SessionLocal

class R:
    def __init__(s, code=200, body=None): s.status_code, s._b = code, body or {}
    def json(s): return s._b

def fake_google(state):
    day = (datetime.now(timezone.utc) + timedelta(days=1)).replace(hour=15, minute=0, second=0, microsecond=0)
    def req(method, url, **kw):
        if url == google.TOKEN:
            if state.get("refresh_fails") and kw["data"]["grant_type"] == "refresh_token": return R(400, {"error": "invalid_grant"})
            return R(200, {"access_token": "at", "refresh_token": "rt", "expires_in": 3600, "scope": " ".join(google.SCOPES)})
        if "userinfo" in url: return R(200, {"email": "me@gmail.com"})
        if url == google.REVOKE: state["revoked"] = True; return R(200)
        if url.endswith("/history"): return R(404) if state.get("history_404") else R(200, {"history": []})
        if url.endswith("/messages"): return R(200, {"messages": [{"id": "m1"}, {"id": "m2"}]})
        if "/messages/" in url:
            subj = {"m1": "Interview invitation Acme", "m2": "Acme application deadline"}[url.rsplit("/", 1)[1]]
            snip = "Interview on 22 Oct 2026 3:00 PM." if subj.startswith("Interview") else "Applications close 24 Oct 2026 5:00 PM."
            return R(200, {"threadId": "t", "snippet": snip, "payload": {"headers": [{"name": "From", "value": "pri@acme.com"}, {"name": "Subject", "value": subj}, {"name": "Date", "value": "Mon, 19 Oct 2026 10:00:00 +0000"}]}})
        if url.endswith("/profile"): return R(200, {"historyId": "100"})
        if "calendar" in url:
            if kw["params"].get("syncToken") and state.get("cal_410") and not state.pop("cal_410_done", None): state["cal_410_done"] = 1; return R(410)
            ev = lambda i, a, b: {"id": i, "summary": i, "start": {"dateTime": (day + timedelta(hours=a)).isoformat()}, "end": {"dateTime": (day + timedelta(hours=b)).isoformat()}}
            return R(200, {"items": [ev("exam", 0, 2), ev("interview", 1, 2)], "nextSyncToken": "S1"})
        raise AssertionError(url)
    return req

def connect(c, mp, state):
    mp.setattr(settings, "google_client_id", "id"); mp.setattr(settings, "google_client_secret", "sec"); mp.setattr(google, "request", fake_google(state))
    url = c.get("/integrations/google/connect").json()["url"]; q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["scope"][0].count("readonly") == 2 and q["access_type"] == ["offline"]  # read-only scopes only
    r = c.get("/integrations/google/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert r.headers["location"] == "/app/?connected=google"; return q

def test_full_google_flow(monkeypatch):
    c, uid = mk_client("goog@x.com"); state = {}; connect(c, monkeypatch, state)
    acc = c.get("/integrations").json()["accounts"][0]; assert acc["email"] == "me@gmail.com" and acc["status"] == "active"
    with SessionLocal() as db: assert "rt" not in db.get(models.ConnectedAccount, acc["id"]).refresh_token_enc  # encrypted at rest
    assert c.post(f"/integrations/{acc['id']}/sync").json() == {"emails": 2, "events": 2}
    state["history_404"] = True; assert c.post(f"/integrations/{acc['id']}/sync").json()["emails"] == 0  # history expired -> full resync, deduped
    b = c.get("/briefing").json(); assert b["conflicts"] and any("Interview" in t["title"] for t in b["tasks"])
    state["cal_410"] = True; assert c.post(f"/integrations/{acc['id']}/sync").status_code == 200  # 410 syncToken handled
    assert c.delete(f"/integrations/{acc['id']}").json()["status"] == "revoked" and state["revoked"]
    assert c.get("/integrations").json()["accounts"][0]["status"] == "revoked"
    assert c.post(f"/integrations/{acc['id']}/sync").status_code == 409

def test_oauth_state_tamper_and_consent_denied(monkeypatch):
    c, _ = mk_client("tamper@x.com"); monkeypatch.setattr(settings, "google_client_id", "id")
    assert c.get("/integrations/google/callback", params={"code": "c", "state": "forged"}).status_code == 400
    assert c.get("/integrations/google/callback", params={"error": "access_denied"}, follow_redirects=False).headers["location"].endswith("consent_denied")

def test_expired_refresh_marks_needs_reauth(monkeypatch):
    c, _ = mk_client("exp@x.com"); state = {}; connect(c, monkeypatch, state); aid = c.get("/integrations").json()["accounts"][0]["id"]
    with SessionLocal() as db: a = db.get(models.ConnectedAccount, aid); a.access_expires_at = datetime(2020, 1, 1, tzinfo=timezone.utc); db.commit()
    state["refresh_fails"] = True; assert c.post(f"/integrations/{aid}/sync").status_code == 401
    assert c.get("/integrations").json()["accounts"][0]["status"] == "needs_reauth"

def test_other_user_cannot_touch_account(monkeypatch):
    a, _ = mk_client("own@x.com"); b, _ = mk_client("thief@x.com"); connect(a, monkeypatch, {}); aid = a.get("/integrations").json()["accounts"][0]["id"]
    assert b.delete(f"/integrations/{aid}").status_code == 404 and b.post(f"/integrations/{aid}/sync").status_code == 404

def test_webhooks(monkeypatch):
    calls = []; monkeypatch.setattr(webhooks, "run_sync", lambda *a: calls.append(a)); t = TestClient(app)
    assert t.post("/webhooks/gmail?token=x", json={}).status_code == 503  # unconfigured
    monkeypatch.setattr(settings, "webhook_secret", "s3cret"); body = {"message": {"data": base64.b64encode(json.dumps({"emailAddress": "nobody@gmail.com", "historyId": "1"}).encode()).decode()}}
    assert t.post("/webhooks/gmail?token=bad", json=body).status_code == 403
    assert t.post("/webhooks/gmail?token=s3cret", json=body).json() == {"queued": 0}
    assert t.post("/webhooks/gmail?token=s3cret", json={"x": 1}).status_code == 400
    assert t.post("/webhooks/calendar", headers={"x-goog-channel-token": "s3cret", "x-goog-resource-state": "sync", "x-goog-channel-id": "A"}).status_code == 200 and not calls
    t.post("/webhooks/calendar", headers={"x-goog-channel-token": "s3cret", "x-goog-resource-state": "exists", "x-goog-channel-id": "A"}); assert calls == [("A", "calendar")]
    assert t.post("/webhooks/microsoft?validationToken=abc").text == "abc"
    assert t.post("/webhooks/microsoft?aid=A", json={"value": [{"clientState": "wrong"}]}).status_code == 403

def test_anomaly_model():
    mk = lambda i, h, subj, snip, snd: NS(id=str(i), received_at=datetime(2026, 10, 1, h, tzinfo=timezone.utc), subject=subj, snippet=snip, sender=snd)
    assert ml.anomaly_scores([mk(0, 10, "a", "b", "x@y.com")])["status"] == "insufficient_data"
    mails = [mk(i, 9 + i % 8, f"Class notes {i}", "See attached notes for the week", "prof@college.edu") for i in range(60)]
    mails.append(mk(99, 3, "URGENT!!! ACT NOW", "Click https://a.co https://b.co immediately last chance 99999", "hr@gmail.com"))
    out = ml.anomaly_scores(mails); assert out["items"][0]["email_id"] == "99" and out["items"][0]["because"]

def test_e2e_workflow_and_ocr_not_faked():
    c, _ = mk_client("e2e@x.com")
    assert c.post("/documents", files={"file": ("n.txt", b"Interview on 30 Dec 2030 10:00 AM.", "text/plain")}).json()["facts_found"] == 1
    assert c.post("/ask", json={"question": "when is my next interview"}).json()["status"] == "grounded"
    tid = c.get("/tasks").json()[0]["id"]; assert c.patch(f"/tasks/{tid}/open").json()["status"] == "open"
    ex = json.dumps(c.get("/export").json()); assert "refresh_token" not in ex and "2030" in ex
    assert c.post("/documents", files={"file": ("s.png", b"\x89PNG", "image/png")}).status_code in (501, 422)
    assert c.delete("/account").json()["deleted"] and c.get("/tasks").status_code == 401

def test_rate_limit_enforced():
    t = TestClient(app); codes = [t.post("/auth/login", json={"email": "no@x.com", "password": "wrongwrongwrong"}).status_code for _ in range(12)]
    assert codes[0] == 401 and codes[-1] == 429

def test_ui_served_and_api_still_routes():
    t = TestClient(app); r = t.get("/app/"); assert r.status_code == 200 and "textContent" in r.text and "Open the app" in t.get("/").text
    assert t.get("/health").json()["status"] == "ok" and t.get("/metrics").json()["requests"] >= 1

def test_inbox_calendar_graph_audit_isolated():
    a, uid = mk_client("gr-a@x.com"); b, _ = mk_client("gr-b@x.com")
    a.post("/documents", files={"file": ("n.txt", b"Interview on 30 Dec 2030 10:00 AM.", "text/plain")})
    g = a.get("/graph").json(); kinds = {n["type"] for n in g["nodes"]}
    assert {"document", "fact", "task"} <= kinds and len(g["edges"]) == 2 and all(n.get("evidence") for n in g["nodes"] if n["type"] == "fact")
    assert b.get("/graph").json() == {"nodes": [], "edges": []} and b.get("/emails").json() == [] and b.get("/events").json() == []
    assert any(x["action"] == "document_uploaded" for x in a.get("/audit").json()) and not any(x["action"] == "document_uploaded" for x in b.get("/audit").json())
