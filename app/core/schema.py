"""Досоздание колонок при обновлении панели.

`Base.metadata.create_all` добавляет недостающие таблицы, но не колонки в уже
существующих. Поэтому после обновления, добавившего поле, панель падала бы на
первом же запросе. Здесь перечислены такие добавления: каждое выполняется
через `ADD COLUMN IF NOT EXISTS`, то есть повторный запуск безвреден.

Порядок действий при добавлении нового поля в модель:
  1. добавить поле в модель;
  2. дописать сюда строку с тем же типом и значением по умолчанию.
"""

from typing import List, Tuple

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

# (таблица, колонка, определение)
COLUMNS: List[Tuple[str, str, str]] = [
    ("users", "device_limit", "INTEGER"),
    ("users", "device_count", "INTEGER DEFAULT 0 NOT NULL"),
    ("users", "devices_seen_at", "TIMESTAMP WITHOUT TIME ZONE"),
    ("hosts", "security", "VARCHAR(16)"),
]


async def ensure_columns(engine: AsyncEngine) -> None:
    async with engine.begin() as connection:
        for table, column, definition in COLUMNS:
            exists = await connection.scalar(
                text(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_name = :table"
                ),
                {"table": table},
            )
            if not exists:
                # Таблицы ещё нет — её создаст create_all уже с этой колонкой.
                continue

            await connection.execute(
                text(
                    f'ALTER TABLE "{table}" '
                    f'ADD COLUMN IF NOT EXISTS "{column}" {definition}'
                )
            )
    logger.debug("Схема проверена: недостающие колонки добавлены")
