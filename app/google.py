"""Google OAuth 2.0 + Gmail/Calendar incremental sync. Read-only scopes. Requires real credentials to run."""
import time, urllib.parse
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import httpx
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session
from .config import settings
from .security import encrypt, decrypt
from . import models
from .intelligence import ingest_email

SCOPES = ["openid", "email", "https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/calendar.readonly"]
AUTH, TOKEN, REVOKE = "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://oauth2.googleapis.com/revoke"

class NeedsReauth(Exception): ...
def configured(): return bool(settings.google_client_id and settings.google_client_secret)
def _state(): return URLSafeTimedSerializer(settings.secret_key, salt="oauth-state")

def auth_url(user_id: str) -> str:
    q = {"client_id": settings.google_client_id, "redirect_uri": settings.google_redirect_uri, "response_type": "code",
         "scope": " ".join(SCOPES), "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true",
         "state": _state().dumps(user_id)}
    return AUTH + "?" + urllib.parse.urlencode(q)

def parse_state(s: str): return _state().loads(s, max_age=600)

def request(method, url, retries=4, **kw):
    """HTTP with exponential backoff on 429/5xx."""
    for i in range(retries):
        r = httpx.request(method, url, timeout=20, **kw)
        if r.status_code in (429, 500, 502, 503, 504) and i < retries - 1:
            time.sleep(min(2 ** i, 8)); continue
        return r

def exchange_code(db: Session, user_id: str, code: str) -> models.ConnectedAccount:
    r = request("POST", TOKEN, data={"code": code, "client_id": settings.google_client_id, "client_secret": settings.google_client_secret,
                                     "redirect_uri": settings.google_redirect_uri, "grant_type": "authorization_code"})
    if r.status_code != 200: raise NeedsReauth(f"Token exchange failed: {r.status_code}")
    t = r.json()
    me = request("GET", "https://openidconnect.googleapis.com/v1/userinfo", headers={"Authorization": f"Bearer {t['access_token']}"}).json()
    acc = db.query(models.ConnectedAccount).filter_by(user_id=user_id, provider="google", external_email=me["email"]).first() \
          or models.ConnectedAccount(user_id=user_id, provider="google", external_email=me["email"])
    if t.get("refresh_token"): acc.refresh_token_enc = encrypt(t["refresh_token"])
    acc.access_token_enc = encrypt(t["access_token"])
    acc.access_expires_at = datetime.now(timezone.utc) + timedelta(seconds=t.get("expires_in", 3600) - 60)
    acc.scopes, acc.status, acc.last_error = t.get("scope", ""), "active", ""
    db.add(acc); db.commit()
    return acc

def access_token(db: Session, acc: models.ConnectedAccount) -> str:
    exp = acc.access_expires_at
    if exp and exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if acc.access_token_enc and exp and exp > datetime.now(timezone.utc): return decrypt(acc.access_token_enc)
    r = request("POST", TOKEN, data={"client_id": settings.google_client_id, "client_secret": settings.google_client_secret,
                                     "refresh_token": decrypt(acc.refresh_token_enc), "grant_type": "refresh_token"})
    if r.status_code != 200:  # invalid_grant = user revoked or token expired
        acc.status, acc.last_error = "needs_reauth", f"Refresh failed ({r.status_code}). Reconnect required."; db.commit()
        raise NeedsReauth(acc.last_error)
    t = r.json(); acc.access_token_enc = encrypt(t["access_token"])
    acc.access_expires_at = datetime.now(timezone.utc) + timedelta(seconds=t.get("expires_in", 3600) - 60); db.commit()
    return t["access_token"]

def revoke(db: Session, acc: models.ConnectedAccount):
    tok = decrypt(acc.refresh_token_enc) or decrypt(acc.access_token_enc)
    if tok:
        try: request("POST", REVOKE, params={"token": tok}, retries=1)
        except httpx.HTTPError: pass
    acc.refresh_token_enc = acc.access_token_enc = ""; acc.status = "revoked"; db.commit()

def _h(msg, name):
    return next((h["value"] for h in msg.get("payload", {}).get("headers", []) if h["name"].lower() == name), "")

def sync_gmail(db: Session, acc: models.ConnectedAccount) -> int:
    tok, base, n = access_token(db, acc), "https://gmail.googleapis.com/gmail/v1/users/me", 0
    H = {"Authorization": f"Bearer {tok}"}
    ids, page = [], None
    def full_list():
        pt = None
        while True:
            r = request("GET", f"{base}/messages", headers=H, params={"q": "newer_than:30d", "maxResults": 100, **({"pageToken": pt} if pt else {})}).json()
            ids.extend(m["id"] for m in r.get("messages", [])); pt = r.get("nextPageToken")
            if not pt: return
    if acc.gmail_history_id:
        while True:
            r = request("GET", f"{base}/history", headers=H, params={"startHistoryId": acc.gmail_history_id, "historyTypes": "messageAdded", **({"pageToken": page} if page else {})})
            if r.status_code == 404: ids.clear(); full_list(); break  # history expired -> full resync
            j = r.json()
            ids.extend(m["message"]["id"] for h in j.get("history", []) for m in h.get("messagesAdded", []))
            page = j.get("nextPageToken")
            if not page: break
    else: full_list()
    for mid in dict.fromkeys(ids):
        if db.query(models.Email).filter_by(account_id=acc.id, provider_id=mid).first(): continue  # idempotent
        m = request("GET", f"{base}/messages/{mid}", headers=H, params={"format": "metadata", "metadataHeaders": ["From", "Subject", "Date"]}).json()
        try: when = parsedate_to_datetime(_h(m, "date")).astimezone(timezone.utc)
        except (TypeError, ValueError): when = datetime.now(timezone.utc)
        e = models.Email(user_id=acc.user_id, account_id=acc.id, provider_id=mid, thread_id=m.get("threadId", ""), sender=_h(m, "from"),
                         subject=_h(m, "subject"), snippet=m.get("snippet", ""), received_at=when)
        db.add(e); db.flush(); ingest_email(db, acc.user_id, e); n += 1
    prof = request("GET", f"{base}/profile", headers=H).json(); acc.gmail_history_id = str(prof.get("historyId", acc.gmail_history_id)); db.commit()
    return n

def sync_calendar(db: Session, acc: models.ConnectedAccount) -> int:
    H, n, pt = {"Authorization": f"Bearer {access_token(db, acc)}"}, 0, None
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    while True:
        p = {"maxResults": 250, "singleEvents": "true", **({"pageToken": pt} if pt else {})}
        if acc.calendar_sync_token: p["syncToken"] = acc.calendar_sync_token
        else: p["timeMin"] = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        r = request("GET", url, headers=H, params=p)
        if r.status_code == 410: acc.calendar_sync_token = ""; db.commit(); pt = None; continue  # token expired -> full resync
        j = r.json()
        for it in j.get("items", []):
            row = db.query(models.CalendarEvent).filter_by(account_id=acc.id, provider_id=it["id"]).first()
            if it.get("status") == "cancelled":
                if row: db.delete(row)
                continue
            s, e = it.get("start", {}), it.get("end", {})
            st = datetime.fromisoformat((s.get("dateTime") or s.get("date") + "T00:00:00+00:00").replace("Z", "+00:00"))
            en = datetime.fromisoformat((e.get("dateTime") or e.get("date") + "T00:00:00+00:00").replace("Z", "+00:00"))
            row = row or models.CalendarEvent(user_id=acc.user_id, account_id=acc.id, provider_id=it["id"])
            row.title, row.starts_at, row.ends_at, row.location = it.get("summary", "(no title)"), st, en, it.get("location", "")
            db.add(row); n += 1
        pt = j.get("nextPageToken")
        if not pt:
            acc.calendar_sync_token = j.get("nextSyncToken", acc.calendar_sync_token); break
    db.commit(); return n

def start_watch(db: Session, acc: models.ConnectedAccount):
    """Register Gmail (Pub/Sub topic) and Calendar push channels. Expire ~7 days: renew from the worker."""
    H = {"Authorization": f"Bearer {access_token(db, acc)}"}
    if not (settings.gmail_pubsub_topic and settings.webhook_secret): raise RuntimeError("Set GMAIL_PUBSUB_TOPIC and WEBHOOK_SECRET")
    g = request("POST", "https://gmail.googleapis.com/gmail/v1/users/me/watch", headers=H, json={"topicName": settings.gmail_pubsub_topic, "labelIds": ["INBOX"]})
    c = request("POST", "https://www.googleapis.com/calendar/v3/calendars/primary/events/watch", headers=H,
                json={"id": acc.id, "type": "web_hook", "address": settings.public_url + "/webhooks/calendar", "token": settings.webhook_secret})
    return {"gmail": g.status_code, "calendar": c.status_code}
