"""Выдача подписки клиентам.

Адрес совпадает со старым Marzban (`/{SUBSCRIPTION_PATH}/{token}`), токены
проверяются его же алгоритмом — поэтому ссылки, которые уже стоят у
пользователей в приложениях, продолжают работать.
"""

from base64 import b64encode
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.user import User
from app.services import users as user_service
from app.services.subscription import get_subscription_payload

router = APIRouter(tags=["subscription"])


async def _resolve_user(session: AsyncSession, token: str) -> User:
    payload = get_subscription_payload(token)
    if payload is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ссылка недействительна")

    user = await user_service.get_user(session, payload["username"])
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ссылка недействительна")

    # Отозванная подписка: токены, выпущенные до отзыва, больше не годятся.
    if user.sub_revoked_at and payload["created_at"] < user.sub_revoked_at.replace(
        microsecond=0
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ссылка отозвана")

    return user


def _user_info_header(user: User) -> str:
    """Заголовок subscription-userinfo — клиенты показывают из него остаток."""
    upload = 0
    download = user.used_traffic
    total = user.data_limit or 0
    expire = user.expire or 0
    return f"upload={upload}; download={download}; total={total}; expire={expire}"


def _headers(user: User) -> dict:
    title = b64encode(settings.SUBSCRIPTION_TITLE.encode("utf-8")).decode("utf-8")
    return {
        "content-disposition": f'attachment; filename="{user.username}"',
        "profile-title": f"base64:{title}",
        "profile-update-interval": str(settings.SUBSCRIPTION_UPDATE_INTERVAL),
        "subscription-userinfo": _user_info_header(user),
        "profile-web-page-url": settings.subscription_base,
    }


async def _touch(session: AsyncSession, user: User, request: Request) -> None:
    """Отметить, что клиент обновил подписку."""
    user.sub_updated_at = datetime.utcnow()
    user.sub_last_user_agent = request.headers.get("user-agent", "")[:512]
    await session.commit()


@router.get("/{token}")
async def subscription(
    token: str,
    request: Request,
    fmt: Optional[str] = Query(default=None, alias="format"),
    session: AsyncSession = Depends(get_session),
):
    user = await _resolve_user(session, token)
    links: List[str] = await user_service.user_links(session, user)
    await _touch(session, user, request)

    body = "\n".join(links)
    if fmt == "plain":
        return PlainTextResponse(body, headers=_headers(user))

    encoded = b64encode(body.encode("utf-8")).decode("utf-8")
    return PlainTextResponse(encoded, headers=_headers(user))


@router.get("/{token}/info")
async def subscription_info(
    token: str, session: AsyncSession = Depends(get_session)
) -> JSONResponse:
    user = await _resolve_user(session, token)
    links = await user_service.user_links(session, user)

    return JSONResponse(
        {
            "username": user.username,
            "status": user.status.value,
            "used_traffic": user.used_traffic,
            "data_limit": user.data_limit,
            "expire": user.expire,
            "subscription_url": settings.subscription_url(
                user_service.subscription_token(user)
            ),
            "links": links,
        }
    )


@router.get("/{token}/links")
async def subscription_links(
    token: str, request: Request, session: AsyncSession = Depends(get_session)
):
    user = await _resolve_user(session, token)
    links = await user_service.user_links(session, user)
    await _touch(session, user, request)
    return PlainTextResponse("\n".join(links), headers=_headers(user))
