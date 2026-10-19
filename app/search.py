"""Ask LifeMesh: extractive, evidence-grounded answers. Every statement is a stored record with a citation.
No generative model is used, so nothing can be invented. Untrusted text is only quoted, never obeyed."""
import re, hashlib, math
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from . import models

STOP = set("what when which does have the and for are was with that this from has not any about latest".split())
INJ = re.compile(r"ignore (all |any )?(previous|prior) instructions|system prompt|reveal .{0,30}(data|users?|passwords?)|you are now", re.I)
def toks(s): return {t for t in re.findall(r"[a-z0-9]{3,}", s.lower()) if t not in STOP}

def embed(text, dim=256):
    """Local hashed word/bigram vector. Lexical similarity only (no synonyms); swap in a neural/pgvector embedder if you configure one."""
    w = re.findall(r"[a-z0-9]{2,}", text.lower()); v = [0.0] * dim
    for g in w + [a + "_" + b for a, b in zip(w, w[1:])]:
        h = int(hashlib.md5(g.encode()).hexdigest(), 16); v[h % dim] += 1 if (h >> 8) & 1 else -1
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]
def cos(a, b): return sum(x * y for x, y in zip(a, b))

def _cite(kind, rec_id, text, extra=None):
    return {"type": kind, "id": rec_id, "quote": text[:300], "flag": "Contains instruction-like text; ignored." if INJ.search(text) else None, **(extra or {})}

def retrieve(db: Session, uid: str, q: str, limit=5):
    qt, hits, qv = toks(q), [], embed(q)
    def add(kind, rid, text, extra=None):
        o = len(qt & toks(text)); s = o + 3 * max(cos(qv, embed(text)), 0)  # hybrid: keyword overlap + vector similarity
        if o or s > 1.2: hits.append((s, _cite(kind, rid, text, extra)))
    for e in db.query(models.Email).filter_by(user_id=uid): add("email", e.id, f"{e.subject}. {e.snippet}")
    for f in db.query(models.Fact).filter_by(user_id=uid): add("fact", f.id, f"{f.kind} {f.evidence}", {"current": f.current, "value": f.value})
    for d in db.query(models.Document).filter_by(user_id=uid): add("document", d.id, f"{d.filename}. {d.text[:400]}")
    for ev in db.query(models.CalendarEvent).filter_by(user_id=uid): add("calendar_event", ev.id, f"{ev.title} {ev.starts_at:%d %b %H:%M}")
    return [h for _, h in sorted(hits, key=lambda x: -x[0])[:limit]]

def ask(db: Session, uid: str, q: str):
    ql, now = q.lower(), datetime.now(timezone.utc)
    if "interview" in ql and ("next" in ql or "when" in ql):
        fs = [f for f in db.query(models.Fact).filter_by(user_id=uid, kind="interview", current=True)
              if datetime.fromisoformat(f.value) >= now]
        if fs:
            f = min(fs, key=lambda x: x.value)
            return {"answer": f"Next recorded interview: {f.value}.", "citations": [_cite("fact", f.id, f.evidence)], "status": "grounded"}
        return {"answer": "No upcoming interview is recorded in your synced data.", "citations": [], "status": "no_evidence"}
    if "change" in ql:
        a = db.query(models.Alert).filter_by(user_id=uid, kind="change").order_by(models.Alert.created_at.desc()).first()
        if a:
            o, n = a.detail["old"], a.detail["new"]
            return {"answer": f"{a.title}: {o['value']} -> {n['value']}.", "status": "grounded",
                    "citations": [_cite("fact", o["source_id"], o["evidence"], {"version": "old"}), _cite("fact", n["source_id"], n["evidence"], {"version": "new"})]}
        return {"answer": "No changes have been detected yet.", "citations": [], "status": "no_evidence"}
    hits = retrieve(db, uid, q)
    if not hits: return {"answer": "I could not find evidence for that in your data.", "citations": [], "status": "no_evidence"}
    return {"answer": "Closest matching records (quoted, not interpreted):", "citations": hits, "status": "extractive"}
