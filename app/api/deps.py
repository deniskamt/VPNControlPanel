"""Зависимости авторизации."""

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.security import decode_admin_token
from app.models.admin import Admin


class NotAuthenticated(Exception):
    """Веб-запрос без сессии — обрабатывается редиректом на /login."""


async def _admin_by_username(session: AsyncSession, username: str) -> Optional[Admin]:
    result = await session.execute(
        select(Admin).where(Admin.username == username, Admin.is_active.is_(True))
    )
    return result.scalar_one_or_none()


async def api_admin(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Admin:
    """Bearer-токен из заголовка Authorization (им ходят боты и приложение)."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Требуется авторизация",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = decode_admin_token(header.split(" ", 1)[1].strip())
    if not username:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Токен недействителен",
            headers={"WWW-Authenticate": "Bearer"},
        )

    admin = await _admin_by_username(session, username)
    if admin is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Администратор не найден")
    return admin


async def web_admin(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Admin:
    """Сессионная кука веб-панели."""
    username = request.session.get("admin")
    if not username:
        raise NotAuthenticated()

    admin = await _admin_by_username(session, username)
    if admin is None:
        request.session.clear()
        raise NotAuthenticated()
    return admin


def redirect_to_login(request: Request) -> RedirectResponse:
    target = request.url.path
    suffix = f"?next={target}" if target and target != "/" else ""
    return RedirectResponse(f"/login{suffix}", status_code=status.HTTP_303_SEE_OTHER)
