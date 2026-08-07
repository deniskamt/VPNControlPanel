from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class NodeUserUsage(Base):
    """Часовая агрегация трафика пользователя по нодам."""

    __tablename__ = "node_user_usages"
    __table_args__ = (
        Index("ix_node_user_usage_bucket", "created_at", "user_id", "node_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    node_id: Mapped[int] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"), index=True
    )
    used_traffic: Mapped[int] = mapped_column(BigInteger, default=0)


class NodeUsage(Base):
    """Часовая агрегация общего трафика ноды."""

    __tablename__ = "node_usages"
    __table_args__ = (Index("ix_node_usage_bucket", "created_at", "node_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    node_id: Mapped[int] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"), index=True
    )
    uplink: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink: Mapped[int] = mapped_column(BigInteger, default=0)


class SystemUsage(Base):
    """Суммарный трафик системы за всё время (одна строка)."""

    __tablename__ = "system_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    uplink: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink: Mapped[int] = mapped_column(BigInteger, default=0)
