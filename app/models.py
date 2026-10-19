import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, UniqueConstraint, Index, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def now(): return datetime.now(timezone.utc)
def uid(): return uuid.uuid4().hex
FK = lambda: ForeignKey("users.id", ondelete="CASCADE")

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    pw_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ConnectedAccount(Base):
    __tablename__ = "connected_accounts"
    __table_args__ = (UniqueConstraint("user_id", "provider", "external_email"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(FK(), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    external_email: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[str] = mapped_column(Text, default="")
    refresh_token_enc: Mapped[str] = mapped_column(Text, default="")  # Fernet-encrypted
    access_token_enc: Mapped[str] = mapped_column(Text, default="")
    access_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|needs_reauth|revoked
    sync_gmail: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_calendar: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_minutes: Mapped[int] = mapped_column(Integer, default=15)
    gmail_history_id: Mapped[str] = mapped_column(String(40), default="")
    calendar_sync_token: Mapped[str] = mapped_column(Text, default="")
    last_error: Mapped[str] = mapped_column(Text, default="")

class Email(Base):
    __tablename__ = "emails"
    __table_args__ = (UniqueConstraint("account_id", "provider_id"), Index("ix_email_user_date", "user_id", "received_at"))
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(FK(), index=True)
    account_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provider_id: Mapped[str] = mapped_column(String(100))
    thread_id: Mapped[str] = mapped_column(String(100), default="")
    sender: Mapped[str] = mapped_column(String(320))
    subject: Mapped[str] = mapped_column(Text)
    snippet: Mapped[str] = mapped_column(Text, default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class CalendarEvent(Base):
    __tablename__ = "calendar_events"
    __table_args__ = (UniqueConstraint("account_id", "provider_id"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(FK(), index=True)
    account_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provider_id: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(Text)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    location: Mapped[str] = mapped_column(Text, default="")

class Fact(Base):
    """Versioned extracted fact. Old versions are kept (current=False), never overwritten."""
    __tablename__ = "facts"
    __table_args__ = (Index("ix_fact_key", "user_id", "entity_key", "current"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(FK(), index=True)
    entity_key: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(30))  # deadline|interview|exam|payment_instruction
    value: Mapped[str] = mapped_column(Text)
    current: Mapped[bool] = mapped_column(Boolean, default=True)
    prev_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_type: Mapped[str] = mapped_column(String(20))
    source_id: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[str] = mapped_column(Text)  # exact sentence the fact came from
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(FK(), index=True)
    title: Mapped[str] = mapped_column(Text)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=2)
    effort_hours: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), default="open")  # proposed|open|done
    fact_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_type: Mapped[str] = mapped_column(String(20), default="manual")
    source_id: Mapped[str] = mapped_column(String(32), default="")

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(FK(), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # change|conflict|risk
    title: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(FK(), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
