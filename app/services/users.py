"""Операции над аккаунтами VPN.

Общая логика для веб-панели и для Marzban-совместимого API — чтобы бот и
панель вели себя одинаково.
"""

import secrets
import uuid as uuid_lib
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import DataLimitResetStrategy, ProxyType, UserStatus
from app.models.inbound import Inbound
from app.models.node import Node
from app.models.user import User, UserProxy
from app.services.client_config import build_user_profiles
from app.services.links import build_user_links, secret_of
from app.services.subscription import create_subscription_token

SS_METHODS = ("chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm")


def default_proxy_settings(protocol: ProxyType) -> Dict[str, Any]:
    """Свежие учётные данные для протокола."""
    if protocol in (ProxyType.vless, ProxyType.vmess):
        settings: Dict[str, Any] = {"id": str(uuid_lib.uuid4())}
        if protocol == ProxyType.vless:
            settings["flow"] = ""
        return settings
    if protocol == ProxyType.trojan:
        return {"password": secrets.token_urlsafe(16)}
    return {
        "password": secrets.token_urlsafe(16),
        "method": SS_METHODS[0],
    }


async def get_user(session: AsyncSession, username: str) -> Optional[User]:
    result = await session.execute(
        select(User).where(User.username == username)
    )
    return result.scalar_one_or_none()


async def enabled_inbounds(session: AsyncSession) -> List[Inbound]:
    result = await session.execute(
        select(Inbound).where(Inbound.is_enabled.is_(True)).order_by(Inbound.id)
    )
    return list(result.scalars().all())


async def resolve_inbounds(
    session: AsyncSession,
    protocols: Iterable[ProxyType],
    tags: Optional[Dict[str, List[str]]] = None,
) -> List[Inbound]:
    """Какие inbound'ы выдать пользователю.

    tags — как в Marzban: {"vless": ["VLESS TCP REALITY"], ...}. Если не
    задано, берём все включённые inbound'ы нужных протоколов.
    """
    available = await enabled_inbounds(session)
    protocol_set = set(protocols)
    selected: List[Inbound] = []

    for inbound in available:
        if inbound.protocol not in protocol_set:
            continue
        if tags:
            allowed = tags.get(inbound.protocol.value)
            # Пустой список для протокола в Marzban значит «все inbound'ы».
            if allowed and inbound.tag not in allowed:
                continue
        selected.append(inbound)

    return selected


async def create_user(
    session: AsyncSession,
    username: str,
    *,
    proxies: Optional[Dict[str, Dict[str, Any]]] = None,
    inbound_tags: Optional[Dict[str, List[str]]] = None,
    expire: Optional[int] = None,
    data_limit: Optional[int] = None,
    data_limit_reset_strategy: DataLimitResetStrategy = DataLimitResetStrategy.no_reset,
    status: UserStatus = UserStatus.active,
    note: Optional[str] = None,
    telegram_id: Optional[int] = None,
    admin_id: Optional[int] = None,
) -> User:
    proxies = proxies or {"vless": {}}
    protocols = [ProxyType(name) for name in proxies.keys()]

    user = User(
        username=username,
        status=status,
        expire=expire,
        data_limit=data_limit or None,
        data_limit_reset_strategy=data_limit_reset_strategy,
        note=note,
        telegram_id=telegram_id,
        admin_id=admin_id,
        created_at=datetime.utcnow(),
        last_status_change=datetime.utcnow(),
    )

    for protocol in protocols:
        overrides = proxies.get(protocol.value) or {}
        settings = default_proxy_settings(protocol)
        # Пришедшие извне значения (например, при миграции) имеют приоритет.
        settings.update({k: v for k, v in overrides.items() if v not in (None, "")})
        user.proxies.append(UserProxy(protocol=protocol, settings=settings))

    user.inbounds = await resolve_inbounds(session, protocols, inbound_tags)

    session.add(user)
    await session.flush()
    return user


async def set_proxies(
    session: AsyncSession,
    user: User,
    proxies: Dict[str, Dict[str, Any]],
    inbound_tags: Optional[Dict[str, List[str]]] = None,
) -> None:
    """Привести набор протоколов пользователя к заданному.

    Существующие ключи сохраняются — иначе у пользователя, которому просто
    продлили подписку, сменились бы UUID и все его конфиги умерли.
    """
    wanted = {ProxyType(name) for name in proxies.keys()}
    current = {proxy.protocol: proxy for proxy in user.proxies}

    for protocol in wanted - set(current):
        settings = default_proxy_settings(protocol)
        settings.update(
            {k: v for k, v in (proxies.get(protocol.value) or {}).items() if v}
        )
        user.proxies.append(UserProxy(protocol=protocol, settings=settings))

    for protocol in set(current) - wanted:
        user.proxies.remove(current[protocol])

    for protocol in wanted & set(current):
        overrides = {k: v for k, v in (proxies.get(protocol.value) or {}).items() if v}
        if overrides:
            merged = dict(current[protocol].settings or {})
            merged.update(overrides)
            current[protocol].settings = merged

    user.inbounds = await resolve_inbounds(session, wanted, inbound_tags)


async def revoke_subscription(session: AsyncSession, user: User) -> None:
    """Отозвать подписку: старая ссылка перестаёт работать, ключи меняются."""
    # Токен подписки хранит время с точностью до секунды, а проверка отзыва
    # сравнивает его с sub_revoked_at. Поэтому метку отзыва округляем до
    # секунды и сдвигаем строго вперёд: иначе отзыв в ту же секунду, в
    # которую подписка была выдана, не сменил бы токен и старая ссылка
    # продолжила бы работать.
    moment = datetime.utcnow().replace(microsecond=0)
    previous = (user.sub_revoked_at or user.created_at or moment).replace(microsecond=0)
    if moment <= previous:
        moment = previous + timedelta(seconds=1)
    user.sub_revoked_at = moment
    for proxy in user.proxies:
        settings = dict(proxy.settings or {})
        fresh = default_proxy_settings(proxy.protocol)
        if "id" in settings:
            settings["id"] = fresh["id"]
        if "password" in settings:
            settings["password"] = fresh["password"]
        proxy.settings = settings
    await session.flush()


def subscription_token(user: User) -> str:
    """Токен подписки пользователя.

    Момент создания берём из sub_revoked_at (если подписку отзывали) или из
    created_at — так токен стабилен между вызовами, а отзыв старых ссылок
    работает через сравнение с sub_revoked_at при проверке.
    """
    moment = user.sub_revoked_at or user.created_at or datetime.utcnow()
    return create_subscription_token(user.username, int(moment.timestamp()))


def ensure_credentials(user: User) -> List[ProxyType]:
    """Выдать ключи для протоколов, которых у пользователя ещё нет.

    Подключение, отмеченное у пользователя, но без ключа нужного протокола,
    просто не попадает в подписку: ссылку не из чего собрать. Снаружи это
    выглядит как «выбрал Trojan, а он не появился», причём молча. Поэтому
    ключи выдаются сами — по набору выбранных подключений.
    """
    needed = {inbound.protocol for inbound in user.inbounds}
    have = {proxy.protocol for proxy in user.proxies}

    issued: List[ProxyType] = []
    for protocol in sorted(needed - have, key=lambda item: item.value):
        user.proxies.append(
            UserProxy(protocol=protocol, settings=default_proxy_settings(protocol))
        )
        issued.append(protocol)

    # Ключ может быть на месте, но пустой — так приезжает часть учётных
    # записей из Marzban, где пароль хранился незаполненным. Ссылка из такого
    # ключа собирается внешне правильная, а клиент показывает «empty
    # password» и не подключается. Дозаполняем, не трогая остальное:
    # у shadowsocks рядом лежит выбранный администратором метод.
    for proxy in user.proxies:
        if proxy.protocol not in needed:
            continue
        if secret_of(proxy.protocol, proxy.settings):
            continue
        settings = dict(proxy.settings or {})
        for key, value in default_proxy_settings(proxy.protocol).items():
            if not settings.get(key):
                settings[key] = value
        proxy.settings = settings
        issued.append(proxy.protocol)

    return issued


async def repair_credentials(session: AsyncSession) -> int:
    """Дозаполнить пустые ключи у всех пользователей.

    Часть учётных записей приезжает из Marzban с незаполненным паролем.
    Подписка у такого человека собирается, но клиент на этой строке пишет
    «empty password» — и понять причину, глядя в панель, невозможно: ключ
    вроде бы есть. Проходим по всем один раз при запуске; тем, у кого всё
    в порядке, это ничего не стоит.
    """
    result = await session.execute(select(User))
    repaired = 0

    for user in result.scalars().all():
        if ensure_credentials(user):
            repaired += 1

    if repaired:
        await session.commit()
    return repaired


async def grant_inbound_to_all(session: AsyncSession, inbound: Inbound) -> int:
    """Выдать новое подключение всем пользователям.

    Новый протокол должен появиться у людей сам: иначе администратор создаёт
    подключение, оно поднимается на серверах — и не доезжает ни до кого, пока
    каждому пользователю не проставить галочку руками.
    """
    result = await session.execute(select(User))
    changed = 0

    for user in result.scalars().all():
        if any(item.id == inbound.id for item in user.inbounds):
            continue
        user.inbounds.append(inbound)
        ensure_credentials(user)
        changed += 1

    await session.flush()
    return changed


async def user_links(session: AsyncSession, user: User) -> List[str]:
    result = await session.execute(
        select(Node).where(Node.is_enabled.is_(True)).order_by(Node.sort_order, Node.id)
    )
    return build_user_links(user, list(result.scalars().all()))


async def user_profiles(session: AsyncSession, user: User) -> List[Dict[str, Any]]:
    """Готовые конфиги Xray для JSON-подписки."""
    result = await session.execute(
        select(Node).where(Node.is_enabled.is_(True)).order_by(Node.sort_order, Node.id)
    )
    return build_user_profiles(user, list(result.scalars().all()))


async def usernames_by_ids(
    session: AsyncSession, user_ids: Sequence[int]
) -> Dict[int, str]:
    if not user_ids:
        return {}
    result = await session.execute(
        select(User.id, User.username).where(User.id.in_(user_ids))
    )
    return {row[0]: row[1] for row in result.all()}
