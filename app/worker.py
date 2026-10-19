from celery import Celery
from .config import settings
from .db import SessionLocal
from . import models, google

celery_app = celery = Celery("lifemesh", broker=settings.redis_url, backend=settings.redis_url)
celery.conf.beat_schedule = {"sync-all": {"task": "app.worker.sync_all", "schedule": 300.0}}

@celery.task(name="app.worker.sync_account", autoretry_for=(Exception,), retry_backoff=True, max_retries=5)
def sync_account(account_id: str):
    with SessionLocal() as db:
        a = db.get(models.ConnectedAccount, account_id)
        if not a or a.status != "active": return
        try:
            if a.sync_gmail: google.sync_gmail(db, a)
            if a.sync_calendar: google.sync_calendar(db, a)
        except google.NeedsReauth: pass  # status already set; user must reconnect

@celery.task(name="app.worker.sync_all")
def sync_all():
    with SessionLocal() as db:
        for a in db.query(models.ConnectedAccount).filter_by(status="active").all(): sync_account.delay(a.id)
