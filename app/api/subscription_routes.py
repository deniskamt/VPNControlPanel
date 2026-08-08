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
from app.services import settings_store
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


def _b64_header(value: str) -> str:
    """Заголовки HTTP однострочные и только ASCII, а в тексте бывают и
    кириллица, и переносы строк — поэтому клиенты понимают префикс base64:."""
    encoded = b64encode(value.encode("utf-8")).decode("ascii")
    return f"base64:{encoded}"


def _headers(user: User, options: Optional[dict] = None) -> dict:
    options = options or {}
    title = options.get("subscription_title") or settings.SUBSCRIPTION_TITLE
    interval = options.get("subscription_update_interval") or str(
        settings.SUBSCRIPTION_UPDATE_INTERVAL
    )

    headers = {
        "content-disposition": f'attachment; filename="{user.username}"',
        "profile-title": _b64_header(title),
        "profile-update-interval": interval,
        "subscription-userinfo": _user_info_header(user),
        "profile-web-page-url": settings.subscription_base,
    }

    # Объявление показывается прямо в карточке подписки, ссылка поддержки —
    # отдельной кнопкой. Пустые значения не шлём, иначе клиент рисует пустоту.
    announce = (options.get("announce") or "").strip()
    if announce:
        headers["announce"] = _b64_header(announce)
    announce_url = (options.get("announce_url") or "").strip()
    if announce_url:
        headers["announce-url"] = announce_url
    support_url = (options.get("support_url") or "").strip()
    if support_url:
        headers["support-url"] = support_url

    return headers


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
    options = await settings_store.get_all(session)
    await _touch(session, user, request)

    if fmt == "json":
        # Подключения с усиленной маскировкой живут только здесь: обычная
        # ссылка их параметры передать не умеет.
        profiles = await user_service.user_profiles(session, user)
        return JSONResponse(profiles, headers=_headers(user, options))

    body = "\n".join(links)
    if fmt == "plain":
        return PlainTextResponse(body, headers=_headers(user, options))

    encoded = b64encode(body.encode("utf-8")).decode("utf-8")
    return PlainTextResponse(encoded, headers=_headers(user, options))


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
    options = await settings_store.get_all(session)
    await _touch(session, user, request)
    return PlainTextResponse("\n".join(links), headers=_headers(user, options))
