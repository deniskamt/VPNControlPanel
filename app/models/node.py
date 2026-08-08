from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Column,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import NodeStatus

# Какие inbound'ы поднимаются на какой ноде.
node_inbounds = Table(
    "node_inbounds",
    Base.metadata,
    Column("node_id", ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "inbound_id", ForeignKey("inbounds.id", ondelete="CASCADE"), primary_key=True
    ),
)


class Node(Base, TimestampMixin):
    """VPN-сервер, на котором крутится Xray под управлением нашего агента."""

    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    # Адрес, по которому к ноде подключаются клиенты (домен или IP).
    address: Mapped[str] = mapped_column(String(256))
    # Адрес управляющего агента. Обычно совпадает с address, но может быть
    # приватным IP, если панель и нода в одной сети.
    agent_host: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    agent_port: Mapped[int] = mapped_column(Integer, default=8443)
    agent_token: Mapped[str] = mapped_column(String(128))
    agent_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    # Не проверять сертификат агента (самоподписанный).
    agent_insecure: Mapped[bool] = mapped_column(Boolean, default=True)

    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[NodeStatus] = mapped_column(
        Enum(NodeStatus, native_enum=False, length=16), default=NodeStatus.connecting
    )
    message: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    xray_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    # Версия агента с последнего опроса: по ней видно, где он устарел.
    agent_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_status_change: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Коэффициент учёта трафика (например, дорогая нода = 2.0).
    usage_coefficient: Mapped[float] = mapped_column(Float, default=1.0)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    uplink: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink: Mapped[int] = mapped_column(BigInteger, default=0)

    # Метрики последнего опроса.
    cpu_percent: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    mem_percent: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    uptime_seconds: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # Хеш последнего успешно применённого конфига — чтобы не гонять
    # одинаковый конфиг на ноду каждые 30 секунд.
    config_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    inbounds: Mapped[List["Inbound"]] = relationship(  # noqa: F821
        secondary=node_inbounds, back_populates="nodes", lazy="selectin"
    )

    @property
    def api_host(self) -> str:
        return self.agent_host or self.address

    @property
    def agent_base_url(self) -> str:
        scheme = "https" if self.agent_tls else "http"
        return f"{scheme}://{self.api_host}:{self.agent_port}"

    def __repr__(self) -> str:  # pragma: no cover - отладка
        return f"<Node {self.name} {self.address}>"
