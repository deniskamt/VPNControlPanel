from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Probe(Base, TimestampMixin):
    """Зонд — сервер в стране пользователей (например, в России).

    На нём стоит тот же агент, что и на нодах, но пользователей он не
    обслуживает и в подписку не попадает: панель просит его подключиться
    через каждый сервер так, как это делает приложение пользователя, и
    смотрит, проходит ли соединение.
    """

    __tablename__ = "probes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="Россия")
    # Адрес агента зонда (домен или IP) и его порт.
    address: Mapped[str] = mapped_column(String(256))
    agent_port: Mapped[int] = mapped_column(Integer, default=8443)
    agent_token: Mapped[str] = mapped_column(String(128))
    agent_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    agent_insecure: Mapped[bool] = mapped_column(Boolean, default=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Состояние самого зонда (не серверов): отвечает ли агент.
    status: Mapped[str] = mapped_column(String(16), default="connecting")
    message: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    agent_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    xray_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Результаты последних проверок: {ключ цели: {...}} и {домен: {...}}.
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    results: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    domains: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Самолечение: что зонд может исправлять сам (см. app/services/probe_fix.py).
    auto_hide: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    auto_port: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    auto_domain: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    # Память самолечения: что и когда меняли, какие домены не помогли, журнал.
    fixes: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")

    # NodeClient умеет говорить с любым агентом: ему нужны только эти поля.
    @property
    def api_host(self) -> str:
        return self.address

    @property
    def agent_base_url(self) -> str:
        scheme = "https" if self.agent_tls else "http"
        return f"{scheme}://{self.address}:{self.agent_port}"

    def __repr__(self) -> str:  # pragma: no cover - отладка
        return f"<Probe {self.name} {self.address}>"
