"""Запись в журнал действий."""

from typing import Any, Dict, Optional

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


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
        actor=actor,
        action=action,
        target=target,
        target_type=target_type,
        message=message,
        level=level,
        details=details,
        ip=ip,
    )
    session.add(entry)
    if commit:
        await session.commit()
    logger.info(f"[audit] {actor} {action} {target or ''} {message or ''}".strip())
    return entry
