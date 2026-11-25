"""Служебный ключ зонда.

Чтобы проверить сервер «как пользователь», зонду нужен ключ, который сервер
примет. Заводить для этого пользователя в базе плохо: он попадёт в списки,
в счётчики и в API для ботов. Поэтому ключ живёт отдельно — в настройках
панели — и добавляется в конфиг каждого сервера как ещё один клиент, только
пока в панели есть включённый зонд. Трафик по нему никуда не записывается:
учёт трафика пропускает имена, которых нет среди пользователей.
"""

import json
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import ProxyType, UserStatus
from app.models.node import Node
from app.models.probe import Probe
from app.models.setting import Setting
from app.models.user import User, UserProxy

PROBE_USERNAME = "__probe__"
SETTING_KEY = "probe_identity"
# Hysteria2 зонд не проверяет: ему нужен отдельный клиент, не Xray.
PROTOCOLS = (ProxyType.vless, ProxyType.vmess, ProxyType.trojan, ProxyType.shadowsocks)


def as_user(credentials: dict) -> User:
    """Ключ зонда в виде несохраняемого пользователя: так его понимают
    генераторы конфига сервера и исходящих соединений."""
    user = User(username=PROBE_USERNAME, status=UserStatus.active)
    user.proxies = [
        UserProxy(protocol=ProxyType(protocol), settings=settings)
        for protocol, settings in credentials.items()
    ]
    return user


async def load(session: AsyncSession, create: bool = False) -> Optional[User]:
    """Ключ зонда. create=True — завести, если его ещё нет."""
    row = await session.get(Setting, SETTING_KEY)
    if row is not None and row.value:
        return as_user(json.loads(row.value))
    if not create:
        return None
    from app.services.users import default_proxy_settings

    credentials = {p.value: default_proxy_settings(p) for p in PROTOCOLS}
    session.add(Setting(key=SETTING_KEY, value=json.dumps(credentials)))
    await session.flush()
    return as_user(credentials)


async def for_servers(session: AsyncSession) -> Optional[User]:
    """Ключ, который нужно положить в конфиг серверов: только если есть
    включённый зонд или мост. Нет ни того, ни другого — сервера живут без
    лишнего клиента."""
    enabled = await session.scalar(
        select(func.count(Probe.id)).where(Probe.is_enabled.is_(True))
    )
    # Мосту ключ нужен как выход на иностранные серверы.
    bridges = await session.scalar(
        select(func.count(Node.id)).where(Node.bridge.is_(True), Node.is_enabled.is_(True))
    )
    if not enabled and not bridges:
        return None
    return await load(session, create=bool(bridges))
