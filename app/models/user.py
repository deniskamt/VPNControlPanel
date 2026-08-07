from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import DataLimitResetStrategy, ProxyType, UserStatus

# Какие inbound'ы доступны пользователю.
user_inbounds = Table(
    "user_inbounds",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "inbound_id", ForeignKey("inbounds.id", ondelete="CASCADE"), primary_key=True
    ),
)


class User(Base, TimestampMixin):
    """Аккаунт VPN. Один аккаунт = одна подписка = один набор ключей."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, native_enum=False, length=16), default=UserStatus.active
    )

    used_traffic: Mapped[int] = mapped_column(BigInteger, default=0)
    lifetime_used_traffic: Mapped[int] = mapped_column(BigInteger, default=0)
    data_limit: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    data_limit_reset_strategy: Mapped[DataLimitResetStrategy] = mapped_column(
        Enum(DataLimitResetStrategy, native_enum=False, length=16),
        default=DataLimitResetStrategy.no_reset,
    )
    # Unix timestamp окончания подписки. NULL = бессрочно.
    # BigInteger, а не Integer: «бессрочные» подписки нередко проставляют
    # датой за 2038 годом, и в int32 такое значение не влезает.
    expire: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # Telegram ID владельца — чтобы связать с ботом.
    telegram_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # Сколько устройств разрешено одновременно. NULL — без ограничения.
    # Считается по уникальным адресам в access-логе Xray за последние минуты.
    device_limit: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    devices_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Момент отзыва подписки: токены, выданные раньше, считаются невалидными.
    sub_revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sub_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sub_last_user_agent: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    online_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_status_change: Mapped[Optional[datetime]] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    admin_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("admins.id", ondelete="SET NULL"), nullable=True
    )

    proxies: Mapped[List["UserProxy"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
    inbounds: Mapped[List["Inbound"]] = relationship(  # noqa: F821
        secondary=user_inbounds, lazy="selectin"
    )
    node_access: Mapped[List["UserNodeAccess"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def is_active(self) -> bool:
        return self.status == UserStatus.active

    @property
    def expired(self) -> bool:
        return bool(self.expire) and self.expire <= int(datetime.utcnow().timestamp())

    @property
    def limited(self) -> bool:
        return bool(self.data_limit) and self.used_traffic >= self.data_limit

    def proxy_settings(self, protocol: ProxyType) -> Optional[Dict[str, Any]]:
        for proxy in self.proxies:
            if proxy.protocol == protocol:
                return proxy.settings or {}
        return None

    def access_for(self, node_id: int) -> Optional["UserNodeAccess"]:  # noqa: F821
        for access in self.node_access:
            if access.node_id == node_id:
                return access
        return None

    def allowed_on(self, node_id: int) -> bool:
        """Доступен ли пользователю этот сервер.

        Отсутствие настройки означает «доступен» — иначе каждая новая нода
        была бы закрыта для всех, пока её не отметят вручную.
        """
        access = self.access_for(node_id)
        return access is None or not access.blocked

    @property
    def over_device_limit(self) -> bool:
        return bool(self.device_limit) and self.device_count > self.device_limit

    def __repr__(self) -> str:  # pragma: no cover - отладка
        return f"<User {self.username} {self.status}>"


class UserProxy(Base):
    """Учётные данные пользователя для конкретного протокола.

    vless/vmess -> {"id": uuid, "flow": "xtls-rprx-vision"}
    trojan      -> {"password": "..."}
    shadowsocks -> {"password": "...", "method": "chacha20-ietf-poly1305"}
    """

    __tablename__ = "user_proxies"
    __table_args__ = (UniqueConstraint("user_id", "protocol", name="uq_user_protocol"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    protocol: Mapped[ProxyType] = mapped_column(
        Enum(ProxyType, native_enum=False, length=16)
    )
    settings: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)

    user: Mapped["User"] = relationship(back_populates="proxies")
