"""Deterministic extraction, versioned facts, change/conflict detection and explainable risk rules.
No LLM is called here. Email text is treated as untrusted data: it is only pattern-matched, never executed."""
import re
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from . import models

MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
MON = r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?"
TIME = r"(?:[,\s]+(?:at\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm))?"
DM = re.compile(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+" + MON + r"(?:,?\s+(\d{4}))?" + TIME, re.I)
MD = re.compile(r"\b" + MON + r"\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s+(\d{4}))?" + TIME, re.I)
KINDS = [("interview", r"interview"), ("exam", r"\bexam"), ("deadline", r"deadline|last date|clos(e|es|ing)|due\b")]
IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
ACCT = re.compile(r"(?:a/?c|account)(?:\s*(?:no\.?|number))?\D{0,12}(\d{9,18})", re.I)
UPI = re.compile(r"\b[\w.\-]{2,}@[a-z]{2,}\b")

def _dt(h, ref):
    d = {"dm": lambda g: (g[0], g[1], g[2], g[3:]), "md": lambda g: (g[1], g[0], g[2], g[3:])}[h[0]](h[1])
    day, mon, yr, t = d
    hr = int(t[0]) % 12 + (12 if t[2] and t[2].lower() == "pm" else 0) if t[0] else 0
    return datetime(int(yr) if yr else ref.year, MONTHS[mon[:3].lower()], int(day), hr, int(t[1] or 0) if t[0] else 0, tzinfo=timezone.utc)

def parse_dates(sentence, ref):
    out = []
    for tag, rx in (("dm", DM), ("md", MD)):
        for m in rx.finditer(sentence):
            try: out.append(_dt((tag, m.groups()), ref))
            except ValueError: pass
    return out

def extract_facts(text: str, ref: datetime):
    facts = []
    for s in re.split(r"(?<=[.!?])\s+|\n", text):
        low = s.lower()
        for kind, rx in KINDS:
            if re.search(rx, low):
                for d in parse_dates(s, ref)[:1]:
                    facts.append((kind, d.isoformat(), s.strip())); break
                break
        pay = [f"IFSC {m}" for m in IFSC.findall(s)] + [f"A/C {m}" for m in ACCT.findall(s)] + [f"UPI {m}" for m in UPI.findall(s)]
        if pay: facts.append(("payment_instruction", " | ".join(sorted(pay)), s.strip()))
    return facts

def norm_subject(subj: str) -> str:
    s = subj.lower()
    s = re.sub(r"^((re|fwd|fw|updated?|revised|rescheduled|reminder)\s*:\s*)+", "", s).strip()
    return re.sub(r"\s+", " ", s)

def upsert_fact(db: Session, user_id, key, kind, value, source_type, source_id, evidence):
    """Insert a new version. Returns (fact, previous_fact_or_None). Same value from a new source is ignored."""
    cur = db.query(models.Fact).filter_by(user_id=user_id, entity_key=key, kind=kind, current=True).first()
    if cur and cur.value == value: return cur, None
    f = models.Fact(user_id=user_id, entity_key=key, kind=kind, value=value, source_type=source_type,
                    source_id=source_id, evidence=evidence, prev_id=cur.id if cur else None)
    if cur: cur.current = False
    db.add(f); db.flush()
    return f, cur

# ---- risk: transparent additive rules, each with a plain-language reason ----
FREE = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"}
def domain(addr): 
    m = re.search(r"@([\w.\-]+)", addr or ""); return m.group(1).lower() if m else ""
RULES = [
    ("payment_request", 35, r"(registration|processing|security|training|kit|onboarding)\s+fee|pay\s+(rs|inr|₹|\$)|send\s+money|processing charge", "Asks the candidate to pay money"),
    ("sensitive_info", 30, r"\b(otp|password|cvv|pin\b|aadhaar|passport number|bank login)", "Asks for sensitive credentials or ID numbers"),
    ("urgency", 10, r"\b(immediately|within 24 hours|today only|urgent|last chance|act now)\b", "Uses pressure or urgency wording"),
]
def assess_risk(sender, subject, body, known_domains=(), prior_payment=None, new_payment=None):
    text = f"{subject}\n{body}".lower(); factors = []
    for name, pts, rx, why in RULES:
        if re.search(rx, text, re.I): factors.append({"rule": name, "points": pts, "reason": why, "label": "observed"})
    d = domain(sender)
    if d in FREE and re.search(r"recruit|hr|careers|talent", sender, re.I):
        factors.append({"rule": "free_mail_recruiter", "points": 15, "reason": f"Recruiting-style sender uses free mail ({d})", "label": "observed"})
    for k in known_domains:
        if d and d != k and (k.split(".")[0] in d.split(".")[0] or d.split(".")[0] in k.split(".")[0]) :
            factors.append({"rule": "lookalike_domain", "points": 30, "reason": f"Sender domain {d} resembles but differs from {k} seen earlier", "label": "observed"})
    if prior_payment and new_payment and prior_payment != new_payment:
        factors.append({"rule": "changed_payment_details", "points": 40, "reason": "Payment details differ from those previously saved", "label": "observed"})
    score = min(100, sum(f["points"] for f in factors))
    level = "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {"score": score, "level": level, "factors": factors,
            "note": "Rule-based heuristic. A high score is a reason to verify through an independent channel, not proof of fraud.",
            "verify": "Contact the organization using contact details you found yourself, not those in the message."}

def find_conflicts(events):
    ev = sorted(events, key=lambda e: e.starts_at); out = []
    for i, a in enumerate(ev):
        for b in ev[i + 1:]:
            if b.starts_at >= a.ends_at: break
            out.append((a, b))
    return out

def ingest_email(db: Session, user_id, email: models.Email, body: str = ""):
    """Extract facts from an already-stored email, record changes/risk alerts. Returns list of alert dicts."""
    text = f"{email.subject}\n{body or email.snippet}"
    alerts = []
    for kind, value, evidence in extract_facts(text, email.received_at):
        key = f"{kind}:{norm_subject(email.subject)}"
        fact, prev = upsert_fact(db, user_id, key, kind, value, "email", email.id, evidence)
        if kind in ("deadline", "interview", "exam") and not prev:
            db.add(models.Task(user_id=user_id, title=f"{kind.title()}: {email.subject}", due_at=datetime.fromisoformat(value),
                               status="proposed", fact_id=fact.id, source_type="email", source_id=email.id))
        if prev:
            tasks = db.query(models.Task).filter_by(user_id=user_id, fact_id=prev.id).all()
            for t in tasks: t.fact_id = fact.id
            a = models.Alert(user_id=user_id, kind="change", title=f"{kind} changed", detail={
                "old": {"value": prev.value, "evidence": prev.evidence, "source_id": prev.source_id},
                "new": {"value": value, "evidence": evidence, "source_id": email.id},
                "affected_task_ids": [t.id for t in tasks]})
            db.add(a); alerts.append(a)
            if kind == "payment_instruction":
                r = assess_risk(email.sender, email.subject, text, prior_payment=prev.value, new_payment=value)
                db.add(models.Alert(user_id=user_id, kind="risk", title="Payment details changed", detail=r))
    prior = {domain(e.sender) for e in db.query(models.Email).filter(models.Email.user_id == user_id, models.Email.id != email.id).all()}
    r = assess_risk(email.sender, email.subject, text, known_domains=[d for d in prior if d and d not in FREE])
    if r["score"] >= 30:
        a = models.Alert(user_id=user_id, kind="risk", title=f"Review message: {email.subject[:80]}", detail={**r, "email_id": email.id}); db.add(a); alerts.append(a)
    db.commit()
    return alerts
