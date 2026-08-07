from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.enums import NetworkType, ProxyType, SecurityType
from app.models.node import node_inbounds


class Inbound(Base, TimestampMixin):
    """Описание входящего подключения Xray: протокол, порт, транспорт.

    Один inbound может быть поднят на нескольких нодах — конфиг генерируется
    одинаковый, различается только адрес в ссылке.
    """

    __tablename__ = "inbounds"

    id: Mapped[int] = mapped_column(primary_key=True)
    tag: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    remark: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    protocol: Mapped[ProxyType] = mapped_column(
        Enum(ProxyType, native_enum=False, length=16)
    )
    listen: Mapped[str] = mapped_column(String(64), default="0.0.0.0")
    port: Mapped[int] = mapped_column(Integer)
    network: Mapped[NetworkType] = mapped_column(
        Enum(NetworkType, native_enum=False, length=16), default=NetworkType.tcp
    )
    security: Mapped[SecurityType] = mapped_column(
        Enum(SecurityType, native_enum=False, length=16), default=SecurityType.none
    )
    # Всё, что зависит от транспорта: path, host, serviceName, sni,
    # reality (dest, serverNames, privateKey, publicKey, shortIds, fingerprint),
    # tls (certificateFile, keyFile), flow, shadowsocks method.
    settings: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    sniffing: Mapped[bool] = mapped_column(Boolean, default=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    nodes: Mapped[List["Node"]] = relationship(  # noqa: F821
        secondary=node_inbounds, back_populates="inbounds", lazy="selectin"
    )
    hosts: Mapped[List["Host"]] = relationship(
        back_populates="inbound", cascade="all, delete-orphan", lazy="selectin"
    )

    def opt(self, key: str, default: Any = None) -> Any:
        return (self.settings or {}).get(key, default)

    def __repr__(self) -> str:  # pragma: no cover - отладка
        return f"<Inbound {self.tag} {self.protocol}>"


class Host(Base, TimestampMixin):
    """Переопределение параметров ссылки-подписки для inbound'а.

    Нужен, когда клиент должен ходить не напрямую на ноду, а, например, через
    CDN: адрес/SNI/порт в ссылке отличаются от реальных на сервере.
    Если у inbound'а нет ни одного host'а, ссылка строится по адресу ноды.
    """

    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    inbound_id: Mapped[int] = mapped_column(
        ForeignKey("inbounds.id", ondelete="CASCADE"), index=True
    )
    # Если задан — host применяется только к этой ноде.
    node_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # Шаблон названия. Поддерживает {node}, {country}, {username}, {protocol}.
    remark: Mapped[str] = mapped_column(String(256), default="{node}")
    # Пусто = адрес ноды.
    address: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sni: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    # Шифрование в ссылке может отличаться от серверного: за CDN inbound часто
    # слушает без TLS, а клиент подключается к CDN уже по TLS.
    security: Mapped[Optional[SecurityType]] = mapped_column(
        Enum(SecurityType, native_enum=False, length=16), nullable=True
    )
    alpn: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    allowinsecure: Mapped[bool] = mapped_column(Boolean, default=False)
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    inbound: Mapped["Inbound"] = relationship(back_populates="hosts")

    def __repr__(self) -> str:  # pragma: no cover - отладка
        return f"<Host {self.remark} -> {self.address}>"
