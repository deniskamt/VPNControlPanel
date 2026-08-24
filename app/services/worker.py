"""Фоновые задачи панели."""

import asyncio
from typing import List

from loguru import logger

from app.core.config import settings
from app.core.database import session_scope
from app.services.node_manager import (
    apply_traffic_resets,
    enforce_limits,
    load_nodes,
    load_users,
    poll_node,
    refresh_devices,
    sync_all_nodes,
    sync_node,
)

# Ссылки на «догоняющие» задачи синхронизации, чтобы их не собрал GC.
_pending: set = set()


async def _sync_now() -> None:
    async with session_scope() as session:
        await sync_all_nodes(session)


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
            async with session_scope() as session:
                nodes = await load_nodes(session)
                users = None
                for node in nodes:
                    await poll_node(session, node)
                    if users is None:
                        users = await load_users(session)
                    await sync_node(session, node, users=users)
                await refresh_devices(session, nodes)
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
