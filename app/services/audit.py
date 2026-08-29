"""Запись в журнал действий."""

from typing import Any, Dict, Optional

from loguru import logger
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog

# Длины полей берём у самой таблицы, чтобы они не разъезжались с моделью.
LIMITS = {
    name: column.type.length
    for name, column in AuditLog.__table__.columns.items()
    if isinstance(column.type, String) and column.type.length
}


def fit(field: str, value: Optional[str]) -> Optional[str]:
    """Подрезать значение под колонку.

    Журнал не должен ломать то, что записывает. Длинное имя сервера или
    подробное перечисление изменений роняли всё действие целиком: Postgres
    отвечал «value too long», панель — пятисоткой, а пользователь видел
    Internal Server Error вместо сохранённых настроек.
    """
    limit = LIMITS.get(field)
    if value is None or limit is None or len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


async def log_action(
    session: AsyncSession,
    action: str,
    *,
    actor: str = "system",
    target: Optional[str] = None,
    target_type: Optional[str] = None,
    message: Optional[str] = None,
    level: str = "info",
    details: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
    commit: bool = False,
) -> AuditLog:
    entry = AuditLog(
        actor=fit("actor", actor),
        action=fit("action", action),
        target=fit("target", target),
        target_type=fit("target_type", target_type),
        message=fit("message", message),
        level=fit("level", level),
        # details — JSONB, длина там не ограничена: подробности целиком.
        details=details,
        ip=fit("ip", ip),
    )
    session.add(entry)
    if commit:
        await session.commit()
    logger.info(f"[audit] {actor} {action} {target or ''} {message or ''}".strip())
    return entry
