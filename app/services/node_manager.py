"""Синхронизация нод: заливка конфигов, опрос состояния, учёт трафика.

Схема работы:
  * панель раз в NODE_POLL_INTERVAL опрашивает каждую ноду;
  * если пересчитанный конфиг отличается по хешу от применённого — заливает
    новый (перезапуск Xray происходит только при реальном изменении);
  * забирает счётчики трафика с обнулением и прибавляет дельту пользователям;
  * при смене статуса ноды пишет в журнал и шлёт уведомление в Telegram.
"""

from datetime import datetime
from typing import Dict, List, Optional, Sequence

from loguru import logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.access import UserNodeAccess
from app.models.enums import NodeStatus, UserStatus
from app.models.node import Node
from app.models.usage import NodeUsage, NodeUserUsage, SystemUsage
from app.models.user import User
from app.services import notifier
from app.services.audit import log_action
from app.services.node_client import NodeClient, NodeError
from app.services.xray_config import build_node_config, config_hash


async def load_users(session: AsyncSession) -> List[User]:
    result = await session.execute(select(User))
    return list(result.scalars().all())


async def load_nodes(session: AsyncSession, only_enabled: bool = True) -> List[Node]:
    query = select(Node)
    if only_enabled:
        query = query.where(Node.is_enabled.is_(True))
    result = await session.execute(query.order_by(Node.sort_order, Node.id))
    return list(result.scalars().all())


async def _set_status(
    session: AsyncSession,
    node: Node,
    status: NodeStatus,
    message: Optional[str] = None,
) -> None:
    if node.status == status and node.message == message:
        return

    previous = node.status
    node.status = status
    node.message = message
    node.last_status_change = datetime.utcnow()

    await log_action(
        session,
        action="node.status",
        target=node.name,
        target_type="node",
        level="error" if status == NodeStatus.error else "info",
        message=f"{previous.value} → {status.value}" + (f": {message}" if message else ""),
    )

    if settings.NOTIFY_NODE_STATUS and previous != status:
        if status == NodeStatus.error:
            notifier.notify_background(
                f"🔴 Нода <b>{node.name}</b> ({node.address}) недоступна\n"
                f"<code>{(message or '')[:300]}</code>"
            )
        elif status == NodeStatus.connected and previous == NodeStatus.error:
            notifier.notify_background(
                f"🟢 Нода <b>{node.name}</b> ({node.address}) снова на связи"
            )


async def sync_node(
    session: AsyncSession,
    node: Node,
    users: Optional[Sequence[User]] = None,
    force: bool = False,
) -> bool:
    """Залить конфиг на ноду, если он изменился. True — если залили."""
    if users is None:
        users = await load_users(session)

    config = build_node_config(node, users)
    new_hash = config_hash(config)
    if node.config_hash == new_hash and not force:
        return False

    client = NodeClient(node)
    try:
        result = await client.apply_config(config, new_hash)
    except NodeError as exc:
        await _set_status(session, node, NodeStatus.error, str(exc))
        await session.commit()
        logger.error(f"Не удалось применить конфиг на ноде {node.name}: {exc}")
        return False

    node.config_hash = new_hash
    node.xray_version = result.get("xray_version") or node.xray_version
    node.last_seen_at = datetime.utcnow()
    await _set_status(session, node, NodeStatus.connected)
    await session.commit()
    logger.info(f"Конфиг применён на ноде {node.name} ({len(config['inbounds'])} inbound)")
    return True


async def sync_all_nodes(session: AsyncSession, force: bool = False) -> int:
    users = await load_users(session)
    nodes = await load_nodes(session)
    synced = 0
    for node in nodes:
        if await sync_node(session, node, users=users, force=force):
            synced += 1
    return synced


async def _get_or_create_access(
    session: AsyncSession, user_id: int, node_id: int
) -> UserNodeAccess:
    existing = await session.execute(
        select(UserNodeAccess).where(
            UserNodeAccess.user_id == user_id, UserNodeAccess.node_id == node_id
        )
    )
    access = existing.scalar_one_or_none()
    if access is None:
        access = UserNodeAccess(user_id=user_id, node_id=node_id)
        session.add(access)
        await session.flush()
    return access


async def refresh_devices(session: AsyncSession, nodes: Sequence[Node]) -> int:
    """Собрать с нод адреса подключений и обновить счётчик устройств.

    Адреса складываются по всем нодам: одно устройство, гуляющее между
    серверами, не должно считаться дважды.
    """
    seen: Dict[str, set] = {}
    reachable = False

    for node in nodes:
        if node.status != NodeStatus.connected:
            continue
        try:
            payload = await NodeClient(node).online(settings.DEVICE_WINDOW_MINUTES)
        except NodeError as exc:
            logger.debug(f"Нода {node.name}: не удалось получить список устройств — {exc}")
            continue
        if not payload.get("available"):
            continue
        reachable = True
        for username, addresses in (payload.get("users") or {}).items():
            seen.setdefault(username, set()).update(addresses)

    if not reachable:
        return 0

    result = await session.execute(select(User))
    changed = 0
    now = datetime.utcnow()

    for user in result.scalars().all():
        count = len(seen.get(user.username, ()))
        if user.device_count != count:
            user.device_count = count
            changed += 1
        if count:
            user.devices_seen_at = now

        if user.device_limit and count > user.device_limit:
            await log_action(
                session,
                action="user.device_limit",
                target=user.username,
                target_type="user",
                level="warning",
                message=f"устройств {count} при лимите {user.device_limit}",
                details={"addresses": sorted(seen.get(user.username, ()))[:20]},
            )
            notifier.notify_background(
                f"⚠️ <b>{user.username}</b>: устройств {count} "
                f"при лимите {user.device_limit}"
            )
            if settings.DEVICE_LIMIT_ACTION == "disable" and user.status == UserStatus.active:
                user.status = UserStatus.disabled
                user.last_status_change = now
                await log_action(
                    session,
                    action="user.auto_status",
                    target=user.username,
                    target_type="user",
                    level="warning",
                    message="отключён из-за превышения лимита устройств",
                )

    if changed:
        await session.commit()
    return changed


def _hour_bucket(moment: Optional[datetime] = None) -> datetime:
    moment = moment or datetime.utcnow()
    return moment.replace(minute=0, second=0, microsecond=0)


async def _record_usage(
    session: AsyncSession,
    node: Node,
    per_user: Dict[str, Dict[str, int]],
    total: Dict[str, int],
) -> None:
    """Разложить дельту трафика по пользователям и часовым бакетам."""
    bucket = _hour_bucket()
    coefficient = node.usage_coefficient or 1.0

    usernames = [name for name, value in per_user.items() if value]
    if usernames:
        result = await session.execute(select(User).where(User.username.in_(usernames)))
        users_by_name = {user.username: user for user in result.scalars().all()}
    else:
        users_by_name = {}

    now = datetime.utcnow()
    for username, counters in per_user.items():
        delta = int((counters.get("uplink", 0) + counters.get("downlink", 0)) * coefficient)
        if delta <= 0:
            continue
        user = users_by_name.get(username)
        if user is None:
            # Пользователь удалён из панели, но ещё живёт в конфиге ноды —
            # конфиг доедет на следующей синхронизации.
            continue

        user.used_traffic += delta
        user.lifetime_used_traffic += delta
        user.online_at = now

        # Трафик по каждому серверу отдельно: из него считается лимит на ноду
        # и видно, куда именно ходит пользователь.
        access = await _get_or_create_access(session, user.id, node.id)
        access.used_traffic += delta

        existing = await session.execute(
            select(NodeUserUsage).where(
                NodeUserUsage.created_at == bucket,
                NodeUserUsage.user_id == user.id,
                NodeUserUsage.node_id == node.id,
            )
        )
        row = existing.scalar_one_or_none()
        if row:
            row.used_traffic += delta
        else:
            session.add(
                NodeUserUsage(
                    created_at=bucket,
                    user_id=user.id,
                    node_id=node.id,
                    used_traffic=delta,
                )
            )

    uplink = int(total.get("uplink", 0))
    downlink = int(total.get("downlink", 0))
    if uplink or downlink:
        node.uplink += uplink
        node.downlink += downlink

        existing = await session.execute(
            select(NodeUsage).where(
                NodeUsage.created_at == bucket, NodeUsage.node_id == node.id
            )
        )
        row = existing.scalar_one_or_none()
        if row:
            row.uplink += uplink
            row.downlink += downlink
        else:
            session.add(
                NodeUsage(
                    created_at=bucket,
                    node_id=node.id,
                    uplink=uplink,
                    downlink=downlink,
                )
            )

        system = await session.get(SystemUsage, 1)
        if system is None:
            system = SystemUsage(id=1, uplink=0, downlink=0)
            session.add(system)
        system.uplink += uplink
        system.downlink += downlink


async def poll_node(session: AsyncSession, node: Node) -> None:
    """Один цикл опроса ноды: здоровье, конфиг, статистика."""
    client = NodeClient(node)

    try:
        health = await client.health()
    except NodeError as exc:
        await _set_status(session, node, NodeStatus.error, str(exc))
        await session.commit()
        return

    node.last_seen_at = datetime.utcnow()
    node.xray_version = health.get("xray_version") or node.xray_version
    node.cpu_percent = health.get("cpu_percent")
    node.mem_percent = health.get("mem_percent")
    node.uptime_seconds = health.get("uptime")

    if not health.get("xray_running"):
        await _set_status(
            session, node, NodeStatus.error, health.get("error") or "Xray не запущен"
        )
    else:
        await _set_status(session, node, NodeStatus.connected)

    # Агент мог быть переустановлен и потерять конфиг — тогда хеши разойдутся
    # и конфиг зальётся заново.
    remote_hash = health.get("config_hash") or ""
    if remote_hash != (node.config_hash or ""):
        node.config_hash = None

    await session.commit()

    try:
        stats = await client.stats(reset=True)
    except NodeError as exc:
        logger.warning(f"Нода {node.name}: не удалось снять статистику — {exc}")
        return

    await _record_usage(
        session, node, stats.get("users") or {}, stats.get("total") or {}
    )
    await session.commit()


async def enforce_limits(session: AsyncSession) -> int:
    """Перевести истёкших и превысивших лимит в неактивные статусы."""
    now = int(datetime.utcnow().timestamp())
    changed = 0

    result = await session.execute(
        select(User).where(User.status == UserStatus.active)
    )
    for user in result.scalars().all():
        new_status: Optional[UserStatus] = None
        if user.expire and user.expire <= now:
            new_status = UserStatus.expired
        elif user.data_limit and user.used_traffic >= user.data_limit:
            new_status = UserStatus.limited

        if new_status:
            user.status = new_status
            user.last_status_change = datetime.utcnow()
            changed += 1
            await log_action(
                session,
                action="user.auto_status",
                target=user.username,
                target_type="user",
                message=f"статус → {new_status.value}",
            )

    # Пользователь, которому продлили подписку, должен вернуться в active.
    result = await session.execute(
        select(User).where(User.status.in_([UserStatus.expired, UserStatus.limited]))
    )
    for user in result.scalars().all():
        expired = bool(user.expire) and user.expire <= now
        limited = bool(user.data_limit) and user.used_traffic >= user.data_limit
        if not expired and not limited:
            user.status = UserStatus.active
            user.last_status_change = datetime.utcnow()
            changed += 1
            await log_action(
                session,
                action="user.auto_status",
                target=user.username,
                target_type="user",
                message="статус → active",
            )

    if changed:
        await session.commit()
    return changed


async def reset_users_traffic(session: AsyncSession, user_ids: Sequence[int]) -> None:
    if not user_ids:
        return
    await session.execute(
        update(User).where(User.id.in_(user_ids)).values(used_traffic=0)
    )
    await session.commit()
