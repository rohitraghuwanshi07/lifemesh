"""Microsoft Graph provider (Outlook mail + calendar). Read-only. WRITTEN BUT NEVER RUN against Microsoft."""
import urllib.parse
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from .config import settings
from .security import encrypt, decrypt
from .google import request, NeedsReauth, _state
from . import models
from .intelligence import ingest_email

SCOPES = ["offline_access", "User.Read", "Mail.Read", "Calendars.Read"]
BASE = "https://login.microsoftonline.com/common/oauth2/v2.0"
def configured(): return bool(settings.ms_client_id and settings.ms_client_secret)

def auth_url(user_id):
    return f"{BASE}/authorize?" + urllib.parse.urlencode({"client_id": settings.ms_client_id, "response_type": "code", "redirect_uri": settings.ms_redirect_uri,
        "scope": " ".join(SCOPES), "state": _state().dumps(user_id), "prompt": "consent"})

def _tok(data):
    return request("POST", f"{BASE}/token", data={"client_id": settings.ms_client_id, "client_secret": settings.ms_client_secret, "scope": " ".join(SCOPES), **data})

def exchange_code(db: Session, user_id, code):
    r = _tok({"grant_type": "authorization_code", "code": code, "redirect_uri": settings.ms_redirect_uri})
    if r.status_code != 200: raise NeedsReauth(f"Token exchange failed: {r.status_code}")
    t = r.json(); me = request("GET", "https://graph.microsoft.com/v1.0/me", headers={"Authorization": f"Bearer {t['access_token']}"}).json()
    mail = me.get("mail") or me.get("userPrincipalName")
    acc = db.query(models.ConnectedAccount).filter_by(user_id=user_id, provider="microsoft", external_email=mail).first() or models.ConnectedAccount(user_id=user_id, provider="microsoft", external_email=mail)
    acc.refresh_token_enc, acc.access_token_enc = encrypt(t.get("refresh_token", "")), encrypt(t["access_token"])
    acc.access_expires_at = datetime.now(timezone.utc) + timedelta(seconds=t.get("expires_in", 3600) - 60)
    acc.scopes, acc.status = t.get("scope", ""), "active"; db.add(acc); db.commit(); return acc

def access_token(db, acc):
    exp = acc.access_expires_at.replace(tzinfo=timezone.utc) if acc.access_expires_at and acc.access_expires_at.tzinfo is None else acc.access_expires_at
    if acc.access_token_enc and exp and exp > datetime.now(timezone.utc): return decrypt(acc.access_token_enc)
    r = _tok({"grant_type": "refresh_token", "refresh_token": decrypt(acc.refresh_token_enc)})
    if r.status_code != 200:
        acc.status, acc.last_error = "needs_reauth", "Refresh failed. Reconnect required."; db.commit(); raise NeedsReauth(acc.last_error)
    t = r.json(); acc.access_token_enc = encrypt(t["access_token"])
    if t.get("refresh_token"): acc.refresh_token_enc = encrypt(t["refresh_token"])
    acc.access_expires_at = datetime.now(timezone.utc) + timedelta(seconds=t.get("expires_in", 3600) - 60); db.commit(); return t["access_token"]

def sync_mail(db: Session, acc) -> int:
    H, n = {"Authorization": f"Bearer {access_token(db, acc)}"}, 0
    url = acc.gmail_history_id or "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$select=subject,from,bodyPreview,receivedDateTime,conversationId"
    while url:  # follows @odata.nextLink pages, stores @odata.deltaLink as the cursor
        j = request("GET", url, headers=H).json()
        for m in j.get("value", []):
            if "@removed" in m or db.query(models.Email).filter_by(account_id=acc.id, provider_id=m["id"]).first(): continue
            e = models.Email(user_id=acc.user_id, account_id=acc.id, provider_id=m["id"], thread_id=m.get("conversationId", ""),
                sender=m.get("from", {}).get("emailAddress", {}).get("address", ""), subject=m.get("subject", ""), snippet=m.get("bodyPreview", ""),
                received_at=datetime.fromisoformat(m["receivedDateTime"].replace("Z", "+00:00")))
            db.add(e); db.flush(); ingest_email(db, acc.user_id, e); n += 1
        if "@odata.deltaLink" in j: acc.gmail_history_id = j["@odata.deltaLink"]
        url = j.get("@odata.nextLink")
    db.commit(); return n

def subscribe(db: Session, acc):
    from .config import settings as s
    exp = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    r = request("POST", "https://graph.microsoft.com/v1.0/subscriptions", headers={"Authorization": f"Bearer {access_token(db, acc)}"},
        json={"changeType": "created,updated", "notificationUrl": f"{s.public_url}/webhooks/microsoft?aid={acc.id}", "resource": "me/mailFolders('inbox')/messages",
              "expirationDateTime": exp, "clientState": s.webhook_secret})
    return r.status_code
