import base64, hashlib, hmac, os, time
from collections import defaultdict, deque
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import URLSafeTimedSerializer, BadSignature
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from .config import settings
from .db import get_db
from . import models

def _fernet():
    key = settings.token_key or base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest())
    return Fernet(key)
def encrypt(s: str) -> str: return _fernet().encrypt(s.encode()).decode() if s else ""
def decrypt(s: str) -> str:
    try: return _fernet().decrypt(s.encode()).decode() if s else ""
    except InvalidToken: return ""

def hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    return salt.hex() + ":" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()
def check_pw(pw: str, stored: str) -> bool:
    salt, h = stored.split(":")
    return hmac.compare_digest(hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex(), h)

def _ser(): return URLSafeTimedSerializer(settings.secret_key, salt="session")
def make_session(user_id: str) -> str: return _ser().dumps(user_id)
def read_session(tok: str, max_age=86400 * 7):
    try: return _ser().loads(tok, max_age=max_age)
    except BadSignature: return None

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
def current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    uid = read_session(request.cookies.get("session", ""))
    user = db.get(models.User, uid) if uid else None
    if not user: raise HTTPException(401, "Not signed in")
    if request.method in UNSAFE:  # double-submit CSRF
        c, h = request.cookies.get("csrf", ""), request.headers.get("x-csrf-token", "")
        if not c or not hmac.compare_digest(c, h): raise HTTPException(403, "CSRF check failed")
    return user

_hits: dict[str, deque] = defaultdict(deque)
def rate_limit(limit=10, window=60):  # in-memory; use Redis for multi-process deployments
    def dep(request: Request):
        k = f"{request.url.path}:{request.client.host if request.client else '?'}"
        q, t = _hits[k], time.time()
        while q and q[0] < t - window: q.popleft()
        if len(q) >= limit: raise HTTPException(429, "Too many requests")
        q.append(t)
    return dep

def audit(db: Session, user_id, action, **meta):
    db.add(models.AuditEvent(user_id=user_id, action=action, meta=meta)); db.commit()
