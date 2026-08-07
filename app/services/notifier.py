"""Уведомления администраторам в Telegram.

Используется прямой вызов Bot API — тянуть в панель aiogram ради одного
sendMessage смысла нет.
"""

import asyncio
from typing import Optional

import httpx
from loguru import logger

from app.core.config import settings

_API = "https://api.telegram.org"


async def send_message(text: str, chat_id: Optional[int] = None) -> None:
    if not settings.TELEGRAM_BOT_TOKEN:
        return

    targets = [chat_id] if chat_id else settings.telegram_admin_ids
    if not targets:
        return

    url = f"{_API}/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient(timeout=10) as client:
        for target in targets:
            try:
                response = await client.post(
                    url,
                    json={
                        "chat_id": target,
                        "text": text,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True,
                    },
                )
                if response.status_code != 200:
                    logger.warning(
                        f"Telegram отклонил уведомление для {target}: "
                        f"{response.status_code} {response.text[:200]}"
                    )
            except httpx.HTTPError as exc:
                logger.warning(f"Не удалось отправить уведомление в Telegram: {exc}")


def notify_background(text: str) -> None:
    """Отправить, не блокируя вызывающий код."""
    if not settings.TELEGRAM_BOT_TOKEN:
        return
    task = asyncio.create_task(send_message(text))
    # Держим ссылку, иначе задача может быть собрана GC до отправки.
    _pending.add(task)
    task.add_done_callback(_pending.discard)


_pending: set = set()
