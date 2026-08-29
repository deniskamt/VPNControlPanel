"""Фоновые задачи панели."""

import asyncio
from typing import List

from loguru import logger

from app.core.config import settings
from app.core.database import session_scope
from app.models.node import Node
from app.services.node_manager import (
    apply_traffic_resets,
    enforce_limits,
    load_nodes,
    load_users,
    poll_node,
    refresh_devices,
    sync_node,
)

# Ссылки на «догоняющие» задачи синхронизации, чтобы их не собрал GC.
_pending: set = set()


# Сколько нод обслуживаем одновременно. Ноды независимы, а обход по очереди
# означает, что одна недоступная задерживает все остальные: на каждую уходит
# таймаут, и при десятке серверов круг растягивается на минуты. Именно из-за
# этого только что созданное подключение подолгу не появлялось на живых нодах.
PARALLEL_NODES = 16


async def _serve_node(node_id: int, poll: bool) -> None:
    """Опросить ноду и залить ей конфиг — в своей сессии.

    Своя сессия обязательна: объекты SQLAlchemy привязаны к сессии, и делить
    одну между параллельными задачами нельзя.
    """
    async with session_scope() as session:
        node = await session.get(Node, node_id)
        if node is None or not node.is_enabled:
            return
        if poll:
            await poll_node(session, node)
        await sync_node(session, node, users=await load_users(session))


async def _serve_all(poll: bool) -> None:
    async with session_scope() as session:
        node_ids = [node.id for node in await load_nodes(session)]

    limit = asyncio.Semaphore(PARALLEL_NODES)

    async def one(node_id: int) -> None:
        async with limit:
            try:
                await _serve_node(node_id, poll)
            except Exception as exc:  # noqa: BLE001 - одна нода не роняет круг
                logger.exception(f"Нода {node_id}: {exc}")

    await asyncio.gather(*(one(node_id) for node_id in node_ids))


async def _sync_now() -> None:
    await _serve_all(poll=False)


def trigger_sync() -> None:
    """Разлить конфиг по нодам, не дожидаясь очередного цикла опроса.

    Вызывается после изменений пользователей и inbound'ов, чтобы новый ключ
    заработал сразу, а не через NODE_POLL_INTERVAL секунд.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(_sync_now())
    _pending.add(task)
    task.add_done_callback(_pending.discard)


async def _poll_loop() -> None:
    while True:
        try:
            await _serve_all(poll=True)
            async with session_scope() as session:
                await refresh_devices(session, await load_nodes(session))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - воркер не должен умирать
            logger.exception(f"Ошибка в цикле опроса нод: {exc}")
        await asyncio.sleep(settings.NODE_POLL_INTERVAL)


async def _enforce_loop() -> None:
    while True:
        try:
            async with session_scope() as session:
                # Сначала сброс трафика по стратегии, потом проверка лимитов:
                # иначе тот, кому только что обнулили счётчик, успел бы
                # схватить статус limited.
                reset = await apply_traffic_resets(session)
                if reset:
                    logger.info(f"Сброшен трафик у пользователей: {reset}")
                changed = await enforce_limits(session)
                if changed:
                    logger.info(f"Обновлены статусы пользователей: {changed}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception(f"Ошибка в цикле проверки лимитов: {exc}")
        await asyncio.sleep(settings.ENFORCE_INTERVAL)


def start_workers() -> List[asyncio.Task]:
    return [
        asyncio.create_task(_poll_loop(), name="node-poll"),
        asyncio.create_task(_enforce_loop(), name="enforce-limits"),
    ]


async def stop_workers(tasks: List[asyncio.Task]) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
