import secrets
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session
from .db import Base, engine, get_db
from . import models, google, graph_ms
from .search import ask as ask_q
from fastapi import UploadFile, File
from .security import hash_pw, check_pw, make_session, current_user, rate_limit, audit
from .intelligence import find_conflicts

import os
if os.getenv("AUTO_CREATE", "1") == "1": Base.metadata.create_all(engine)  # dev convenience; production runs `alembic upgrade head`
from . import webhooks, telemetry, ml
app = FastAPI(title="LifeMesh API", version="0.2.0")
app.include_router(webhooks.router); telemetry.setup(app)

class Creds(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=200)

def _login(resp: Response, user_id: str):
    resp.set_cookie("session", make_session(user_id), httponly=True, samesite="lax", secure=False, max_age=604800)  # secure=True behind HTTPS
    resp.set_cookie("csrf", secrets.token_urlsafe(24), httponly=False, samesite="lax")

@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("select 1")); return {"status": "ok", "google_configured": google.configured()}

@app.post("/auth/register", dependencies=[Depends(rate_limit(10, 60))])
def register(c: Creds, resp: Response, db: Session = Depends(get_db)):
    if db.query(models.User).filter_by(email=c.email.lower()).first(): raise HTTPException(409, "Email already registered")
    u = models.User(email=c.email.lower(), pw_hash=hash_pw(c.password)); db.add(u); db.commit()
    _login(resp, u.id); audit(db, u.id, "register"); return {"id": u.id}

@app.post("/auth/login", dependencies=[Depends(rate_limit(10, 60))])
def login(c: Creds, resp: Response, db: Session = Depends(get_db)):
    u = db.query(models.User).filter_by(email=c.email.lower()).first()
    if not u or not check_pw(c.password, u.pw_hash): raise HTTPException(401, "Invalid credentials")
    _login(resp, u.id); audit(db, u.id, "login"); return {"id": u.id}

@app.post("/auth/logout")
def logout(resp: Response, u=Depends(current_user)):
    resp.delete_cookie("session"); resp.delete_cookie("csrf"); return {"ok": True}

# ---- integrations ----
@app.get("/integrations")
def integrations(u=Depends(current_user), db: Session = Depends(get_db)):
    accs = db.query(models.ConnectedAccount).filter_by(user_id=u.id).all()
    return {"google_available": google.configured(), "accounts": [
        {"id": a.id, "provider": a.provider, "email": a.external_email, "status": a.status, "scopes": a.scopes.split(),
         "sync_gmail": a.sync_gmail, "sync_calendar": a.sync_calendar, "sync_minutes": a.sync_minutes, "last_error": a.last_error} for a in accs]}

@app.get("/integrations/google/connect")
def g_connect(u=Depends(current_user)):
    if not google.configured(): raise HTTPException(503, "Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")
    return {"url": google.auth_url(u.id)}

@app.get("/integrations/google/callback")
def g_callback(code: str = "", state: str = "", error: str = "", db: Session = Depends(get_db)):
    if error or not code: return RedirectResponse("/app/?integration_error=consent_denied")
    try: uid = google.parse_state(state)
    except Exception: raise HTTPException(400, "Invalid or expired state")
    try: acc = google.exchange_code(db, uid, code)
    except google.NeedsReauth as e: return RedirectResponse(f"/app/?integration_error={e}")
    audit(db, uid, "google_connected", account=acc.external_email); return RedirectResponse("/app/?connected=google")

class Prefs(BaseModel):
    sync_gmail: bool | None = None
    sync_calendar: bool | None = None
    sync_minutes: int | None = Field(None, ge=5, le=1440)

def _acc(db, u, aid):
    a = db.query(models.ConnectedAccount).filter_by(id=aid, user_id=u.id).first()  # ownership enforced here
    if not a: raise HTTPException(404, "Not found")
    return a

@app.patch("/integrations/{aid}")
def set_prefs(aid: str, p: Prefs, u=Depends(current_user), db: Session = Depends(get_db)):
    a = _acc(db, u, aid)
    for k, v in p.model_dump(exclude_none=True).items(): setattr(a, k, v)
    db.commit(); return {"ok": True}

@app.delete("/integrations/{aid}")
def disconnect(aid: str, u=Depends(current_user), db: Session = Depends(get_db)):
    a = _acc(db, u, aid); google.revoke(db, a); audit(db, u.id, "google_disconnected", account=a.external_email); return {"status": "revoked"}

@app.post("/integrations/{aid}/sync", dependencies=[Depends(rate_limit(6, 60))])
def sync_now(aid: str, u=Depends(current_user), db: Session = Depends(get_db)):
    a = _acc(db, u, aid)
    if a.status != "active": raise HTTPException(409, f"Account is {a.status}. Reconnect it first.")
    try:
        res = {"emails": google.sync_gmail(db, a) if a.sync_gmail else 0, "events": google.sync_calendar(db, a) if a.sync_calendar else 0}
    except google.NeedsReauth as e: raise HTTPException(401, str(e))
    return res

# ---- data ----
class TaskIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    due_at: datetime | None = None
    priority: int = Field(2, ge=1, le=3)
    effort_hours: int = Field(1, ge=1, le=80)

def _task(t): return {"id": t.id, "title": t.title, "due_at": t.due_at, "status": t.status, "priority": t.priority, "fact_id": t.fact_id, "source_id": t.source_id}

@app.post("/tasks")
def add_task(b: TaskIn, u=Depends(current_user), db: Session = Depends(get_db)):
    t = models.Task(user_id=u.id, **b.model_dump()); db.add(t); db.commit(); return _task(t)

@app.get("/tasks")
def tasks(u=Depends(current_user), db: Session = Depends(get_db)):
    return [_task(t) for t in db.query(models.Task).filter_by(user_id=u.id).order_by(models.Task.due_at).all()]

@app.patch("/tasks/{tid}/{status}")
def set_status(tid: str, status: str, u=Depends(current_user), db: Session = Depends(get_db)):
    if status not in ("open", "done"): raise HTTPException(422, "status must be open or done")
    t = db.query(models.Task).filter_by(id=tid, user_id=u.id).first()
    if not t: raise HTTPException(404, "Not found")
    t.status = status; db.commit(); return _task(t)  # 'proposed' -> 'open' is the user's approval

@app.get("/alerts")
def alerts(u=Depends(current_user), db: Session = Depends(get_db)):
    return [{"id": a.id, "kind": a.kind, "title": a.title, "detail": a.detail, "created_at": a.created_at}
            for a in db.query(models.Alert).filter_by(user_id=u.id, resolved=False).order_by(models.Alert.created_at.desc())]

@app.get("/facts/{fact_id}/history")
def history(fact_id: str, u=Depends(current_user), db: Session = Depends(get_db)):
    out, f = [], db.query(models.Fact).filter_by(id=fact_id, user_id=u.id).first()
    while f:
        out.append({"id": f.id, "value": f.value, "evidence": f.evidence, "source": [f.source_type, f.source_id], "current": f.current, "at": f.created_at})
        f = db.query(models.Fact).filter_by(id=f.prev_id, user_id=u.id).first() if f.prev_id else None
    if not out: raise HTTPException(404, "Not found")
    return out

@app.get("/briefing")
def briefing(u=Depends(current_user), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc); end = now + timedelta(days=1)
    ev = db.query(models.CalendarEvent).filter(models.CalendarEvent.user_id == u.id, models.CalendarEvent.starts_at >= now, models.CalendarEvent.starts_at < end + timedelta(days=6)).all()
    tk = db.query(models.Task).filter(models.Task.user_id == u.id, models.Task.status.in_(["open", "proposed"])).all()
    def tz(d): return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)
    ranked = sorted(tk, key=lambda t: ((tz(t.due_at) or now + timedelta(days=365)), -t.priority))
    return {"generated_from": {"events": len(ev), "tasks": len(tk)}, "today": [e.title for e in ev if tz(e.starts_at) < end],
            "conflicts": [[a.title, b.title] for a, b in find_conflicts(ev)], "tasks": [_task(t) for t in ranked[:5]],
            "alerts": len(db.query(models.Alert).filter_by(user_id=u.id, resolved=False).all()), "empty": not ev and not tk}

@app.delete("/account")
def delete_account(resp: Response, u=Depends(current_user), db: Session = Depends(get_db)):
    for a in db.query(models.ConnectedAccount).filter_by(user_id=u.id).all():
        if a.status == "active": google.revoke(db, a)
    for m in (models.Alert, models.Task, models.Fact, models.CalendarEvent, models.Email, models.ConnectedAccount):
        db.query(m).filter_by(user_id=u.id).delete()
    audit(db, u.id, "account_deleted"); db.delete(u); db.commit(); resp.delete_cookie("session"); return {"deleted": True}

# ---- Microsoft ----
@app.get("/integrations/microsoft/connect")
def ms_connect(u=Depends(current_user)):
    if not graph_ms.configured(): raise HTTPException(503, "Microsoft OAuth is not configured. Set MS_CLIENT_ID and MS_CLIENT_SECRET.")
    return {"url": graph_ms.auth_url(u.id)}

@app.get("/integrations/microsoft/callback")
def ms_callback(code: str = "", state: str = "", error: str = "", db: Session = Depends(get_db)):
    if error or not code: return RedirectResponse("/app/?integration_error=consent_denied")
    try: uid = google.parse_state(state)
    except Exception: raise HTTPException(400, "Invalid or expired state")
    try: graph_ms.exchange_code(db, uid, code)
    except google.NeedsReauth as e: return RedirectResponse(f"/app/?integration_error={e}")
    return RedirectResponse("/app/?connected=microsoft")

# ---- documents + Ask ----
MAX_BYTES, ALLOWED = 5 * 1024 * 1024, {".txt", ".md", ".pdf", ".png", ".jpg", ".jpeg"}
@app.post("/documents", dependencies=[Depends(rate_limit(20, 60))])
async def upload(file: UploadFile = File(...), u=Depends(current_user), db: Session = Depends(get_db)):
    import os, io
    from datetime import datetime as dt, timezone as tzn
    from .intelligence import extract_facts, upsert_fact
    name = os.path.basename(file.filename or "upload")[:200]; ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED: raise HTTPException(415, "Only .txt, .md and .pdf are accepted. Image OCR is not configured.")
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES: raise HTTPException(413, "File larger than 5 MB")
    if ext in (".png", ".jpg", ".jpeg"):
        import shutil
        if not shutil.which("tesseract"): raise HTTPException(501, "OCR is not configured: install the tesseract binary (see Dockerfile).")
        try:
            import pytesseract; from PIL import Image
            img = Image.open(io.BytesIO(data)); img.verify(); text = pytesseract.image_to_string(Image.open(io.BytesIO(data)))
        except Exception: raise HTTPException(422, "Could not read this image")
    elif ext == ".pdf":
        if not data.startswith(b"%PDF"): raise HTTPException(415, "Not a valid PDF")
        try:
            from pypdf import PdfReader
            text = "\n".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(data)).pages[:50])
        except Exception: raise HTTPException(422, "Could not read this PDF")
    else: text = data.decode("utf-8", errors="replace")
    d = models.Document(user_id=u.id, filename=name, size=len(data), text=text[:200000]); db.add(d); db.flush()
    n = 0
    for kind, val, ev in extract_facts(text, dt.now(tzn.utc)):
        f, prev = upsert_fact(db, u.id, f"{kind}:{name.lower()}", kind, val, "document", d.id, ev); n += 1
        if kind in ("deadline", "interview", "exam") and not prev:
            db.add(models.Task(user_id=u.id, title=f"{kind.title()}: {name}", due_at=dt.fromisoformat(val), status="proposed", fact_id=f.id, source_type="document", source_id=d.id))
    db.commit(); audit(db, u.id, "document_uploaded", name=name, size=len(data))
    return {"id": d.id, "filename": name, "facts_found": n, "note": "Extracted items are proposals until you approve them."}

class AskIn(BaseModel):
    question: str = Field(min_length=2, max_length=500)

@app.post("/ask", dependencies=[Depends(rate_limit(30, 60))])
def ask_endpoint(b: AskIn, u=Depends(current_user), db: Session = Depends(get_db)):
    return ask_q(db, u.id, b.question)

@app.get("/risk/anomalies")
def anomalies(u=Depends(current_user), db: Session = Depends(get_db)):
    return ml.anomaly_scores(db.query(models.Email).filter_by(user_id=u.id).all())

@app.patch("/alerts/{aid}/resolve")
def resolve(aid: str, u=Depends(current_user), db: Session = Depends(get_db)):
    a = db.query(models.Alert).filter_by(id=aid, user_id=u.id).first()
    if not a: raise HTTPException(404, "Not found")
    a.resolved = True; db.commit(); return {"ok": True}

@app.post("/integrations/{aid}/watch")
def watch(aid: str, u=Depends(current_user), db: Session = Depends(get_db)):
    a = _acc(db, u, aid)
    try: return google.start_watch(db, a) if a.provider == "google" else {"microsoft": graph_ms.subscribe(db, a)}
    except (RuntimeError, google.NeedsReauth) as e: raise HTTPException(503, str(e))

@app.get("/export")
def export(u=Depends(current_user), db: Session = Depends(get_db)):
    rows = lambda m: [{c.name: str(getattr(r, c.name)) for c in m.__table__.columns if "token" not in c.name} for r in db.query(m).filter_by(user_id=u.id)]
    audit(db, u.id, "export"); return {m.__tablename__: rows(m) for m in (models.Email, models.CalendarEvent, models.Fact, models.Task, models.Alert, models.Document)}

@app.get("/emails")
def emails(limit: int = 50, u=Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(models.Email).filter_by(user_id=u.id).order_by(models.Email.received_at.desc()).limit(min(limit, 200)).all()
    kinds = {}
    for f in db.query(models.Fact).filter_by(user_id=u.id, source_type="email"): kinds.setdefault(f.source_id, set()).add(f.kind)
    risky = {a.detail.get("email_id") for a in db.query(models.Alert).filter_by(user_id=u.id, kind="risk", resolved=False)}
    return [{"id": e.id, "sender": e.sender, "subject": e.subject, "snippet": e.snippet, "received_at": e.received_at, "tags": sorted(kinds.get(e.id, [])), "risk": e.id in risky} for e in rows]

@app.get("/events")
def events(days: int = 14, u=Depends(current_user), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc) - timedelta(hours=12)
    q = db.query(models.CalendarEvent).filter(models.CalendarEvent.user_id == u.id, models.CalendarEvent.starts_at >= now, models.CalendarEvent.starts_at < now + timedelta(days=min(days, 60))).order_by(models.CalendarEvent.starts_at)
    return [{"id": e.id, "title": e.title, "starts_at": e.starts_at, "ends_at": e.ends_at, "location": e.location} for e in q]

@app.get("/graph")
def graph(u=Depends(current_user), db: Session = Depends(get_db)):
    """Provenance graph built from real rows: sources -> facts (with version chain) -> tasks. Every node carries its evidence."""
    nodes, edges, src = [], [], {}
    facts = db.query(models.Fact).filter_by(user_id=u.id).order_by(models.Fact.created_at).all()
    for f in facts:
        if (f.source_type, f.source_id) not in src:
            rec = db.get(models.Email, f.source_id) if f.source_type == "email" else db.get(models.Document, f.source_id)
            src[(f.source_type, f.source_id)] = f"s:{f.source_id}"
            nodes.append({"id": f"s:{f.source_id}", "type": f.source_type, "label": (getattr(rec, "subject", None) or getattr(rec, "filename", "") or f.source_type)[:40]})
        nodes.append({"id": f"f:{f.id}", "type": "fact", "label": f.kind, "value": f.value, "current": f.current, "evidence": f.evidence, "at": f.created_at.isoformat()})
        edges.append([src[(f.source_type, f.source_id)], f"f:{f.id}", "extracted"])
        if f.prev_id: edges.append([f"f:{f.id}", f"f:{f.prev_id}", "supersedes"])
    for t in db.query(models.Task).filter(models.Task.user_id == u.id, models.Task.fact_id.isnot(None)):
        nodes.append({"id": f"t:{t.id}", "type": "task", "label": t.title[:40], "status": t.status}); edges.append([f"t:{t.id}", f"f:{t.fact_id}", "tracks"])
    return {"nodes": nodes, "edges": edges}

@app.get("/audit")
def audit_log(u=Depends(current_user), db: Session = Depends(get_db)):
    return [{"action": a.action, "at": a.at, "meta": a.meta} for a in db.query(models.AuditEvent).filter_by(user_id=u.id).order_by(models.AuditEvent.at.desc()).limit(50)]

from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "web"), html=True), name="web")  # must stay last
