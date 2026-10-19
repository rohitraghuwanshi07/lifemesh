"""Push notifications -> incremental sync. Polling (worker.sync_all) remains the fallback. Verified only with simulated payloads."""
import base64, hmac, json
from fastapi import APIRouter, Request, BackgroundTasks, HTTPException, Response
from .config import settings
from .db import SessionLocal
from . import models, google, graph_ms

router = APIRouter(prefix="/webhooks")
def _ok(tok: str):
    if not settings.webhook_secret: raise HTTPException(503, "WEBHOOK_SECRET not configured")
    if not hmac.compare_digest(tok or "", settings.webhook_secret): raise HTTPException(403, "Bad webhook token")

def run_sync(account_id: str, which: str = "both"):
    with SessionLocal() as db:
        a = db.get(models.ConnectedAccount, account_id)
        if not a or a.status != "active": return
        try:
            if a.provider == "google":
                if a.sync_gmail and which in ("gmail", "both"): google.sync_gmail(db, a)
                if a.sync_calendar and which in ("calendar", "both"): google.sync_calendar(db, a)
            elif a.sync_gmail: graph_ms.sync_mail(db, a)
        except Exception as e:  # never raise into the provider; record and let polling recover
            a.last_error = str(e)[:300]; db.commit()

@router.post("/gmail")  # Pub/Sub push: ?token=<WEBHOOK_SECRET>
async def gmail(request: Request, bg: BackgroundTasks, token: str = ""):
    _ok(token)
    try: data = json.loads(base64.b64decode((await request.json())["message"]["data"]))
    except Exception: raise HTTPException(400, "Malformed Pub/Sub message")
    with SessionLocal() as db:
        ids = [a.id for a in db.query(models.ConnectedAccount).filter_by(provider="google", external_email=data.get("emailAddress", ""), status="active")]
    for i in ids: bg.add_task(run_sync, i, "gmail")
    return {"queued": len(ids)}

@router.post("/calendar")  # Calendar watch: channel id = account id, channel token = secret
async def calendar(bg: BackgroundTasks, request: Request):
    _ok(request.headers.get("x-goog-channel-token", ""))
    if request.headers.get("x-goog-resource-state") != "sync":  # "sync" is the handshake ping
        bg.add_task(run_sync, request.headers.get("x-goog-channel-id", ""), "calendar")
    return Response(status_code=200)

@router.post("/microsoft")
async def microsoft(request: Request, bg: BackgroundTasks, aid: str = "", validationToken: str = ""):
    if validationToken: return Response(validationToken, media_type="text/plain")  # subscription handshake
    body = await request.json()
    for n in body.get("value", []):
        _ok(n.get("clientState", ""))
        bg.add_task(run_sync, aid, "gmail")
    return Response(status_code=202)
