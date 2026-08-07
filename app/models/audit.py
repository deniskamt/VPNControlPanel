from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    """Журнал действий: кто, что и над кем сделал.

    Пишется и для веб-панели, и для совместимого API (там actor — имя
    админа из токена), чтобы действия ботов тоже были видны.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_created", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    actor: Mapped[str] = mapped_column(String(64), default="system")
    # user.create, user.update, user.delete, user.reset, node.create, ...
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    target: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    level: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
