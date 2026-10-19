"""Statistical anomaly detection on the user's OWN email history (IsolationForest). Complements rules; never a verdict."""
import re
import numpy as np
from sklearn.ensemble import IsolationForest
from .intelligence import domain, FREE
NAMES = ["hour", "subject_len", "body_len", "digit_ratio", "links", "urgency_words", "free_mail", "caps_ratio"]
def features(e) -> list[float]:
    t = f"{e.subject} {e.snippet}"; n = max(len(t), 1)
    return [e.received_at.hour, len(e.subject), len(e.snippet), sum(c.isdigit() for c in t) / n, len(re.findall(r"https?://", t)),
            len(re.findall(r"urgent|immediately|today only|last chance|act now|within 24", t, re.I)), float(domain(e.sender) in FREE), sum(c.isupper() for c in t) / n]

def anomaly_scores(emails, min_n=30, top=5):
    if len(emails) < min_n: return {"status": "insufficient_data", "needed": min_n, "have": len(emails), "items": []}
    X = np.array([features(e) for e in emails]); med, mad = np.median(X, 0), np.median(np.abs(X - np.median(X, 0)), 0) + 1e-6
    raw = -IsolationForest(n_estimators=200, random_state=0).fit(X).score_samples(X)
    pct = raw.argsort().argsort() / (len(raw) - 1)
    items = []
    for i in np.argsort(-raw)[:top]:
        z = (X[i] - med) / mad; k = np.argsort(-np.abs(z))[:2]
        items.append({"email_id": emails[i].id, "score": int(pct[i] * 100), "because": [f"{NAMES[j]} = {X[i][j]:.2f} vs typical {med[j]:.2f}" for j in k]})
    return {"status": "ok", "method": "IsolationForest on your own history; unusual != malicious", "items": items}
