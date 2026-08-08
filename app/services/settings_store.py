"""Настройки подписки, редактируемые из панели.

Клиентские приложения (v2rayTun, Hiddify и подобные) забирают оформление
профиля из заголовков ответа подписки: название, объявление, ссылку на
поддержку, интервал обновления. Держать это в .env неудобно — текст
объявления меняют часто, а перезапускать панель ради него не хочется.
"""

from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as env_settings
from app.models.setting import Setting

# Ключ -> значение по умолчанию (берётся из .env, где это уместно).
KEYS = (
    "subscription_title",
    "subscription_update_interval",
    "announce",
    "announce_url",
    "support_url",
)


def defaults() -> Dict[str, str]:
    return {
        "subscription_title": env_settings.SUBSCRIPTION_TITLE,
        "subscription_update_interval": str(env_settings.SUBSCRIPTION_UPDATE_INTERVAL),
        "announce": "",
        "announce_url": "",
        "support_url": "",
    }


async def get_all(session: AsyncSession) -> Dict[str, str]:
    """Настройки с подставленными значениями по умолчанию."""
    values = defaults()
    result = await session.execute(select(Setting).where(Setting.key.in_(KEYS)))
    for row in result.scalars().all():
        if row.value is not None:
            values[row.key] = row.value
    return values


async def get(session: AsyncSession, key: str) -> Optional[str]:
    return (await get_all(session)).get(key)


async def save(session: AsyncSession, values: Dict[str, str]) -> None:
    existing = {
        row.key: row
        for row in (await session.execute(select(Setting))).scalars().all()
    }
    for key, value in values.items():
        if key not in KEYS:
            continue
        if key in existing:
            existing[key].value = value
        else:
            session.add(Setting(key=key, value=value))
    await session.flush()
