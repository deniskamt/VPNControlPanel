"""Журнал действий и страница настроек/уведомлений."""

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.config import settings
from app.core.database import get_session
from app.models.admin import Admin
from app.models.audit import AuditLog
from app.services import notifier, settings_store
from app.services.audit import log_action
from app.web.templates import templates

router = APIRouter()

PAGE_SIZE = 50


@router.get("/logs", response_class=HTMLResponse)
async def logs(
    request: Request,
    action: str = Query(default=""),
    level: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action.ilike(f"{action}%"))
    if level:
        query = query.where(AuditLog.level == level)

    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
    result = await session.execute(
        query.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    )

    actions = list(
        (await session.execute(select(AuditLog.action).distinct().order_by(AuditLog.action)))
        .scalars()
        .all()
    )

    return templates.TemplateResponse(
        request,
        "logs.html",
        {
            "admin": admin,
            "page": "logs",
            "entries": list(result.scalars().all()),
            "actions": actions,
            "action": action,
            "level": level,
            "page_number": page,
            "pages": max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
            "total": total,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
    sent: bool = Query(default=False),
    saved: bool = Query(default=False),
):
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "admin": admin,
            "page": "settings",
            "settings": settings,
            "options": await settings_store.get_all(session),
            "sent": sent,
            "saved": saved,
        },
    )


@router.post("/settings/subscription")
async def save_subscription_settings(
    request: Request,
    subscription_title: str = Form(default=""),
    subscription_update_interval: str = Form(default="12"),
    announce: str = Form(default=""),
    announce_url: str = Form(default=""),
    support_url: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Оформление подписки в клиентских приложениях."""
    interval = subscription_update_interval.strip()
    if not interval.isdigit() or not 1 <= int(interval) <= 168:
        interval = "12"

    await settings_store.save(
        session,
        {
            "subscription_title": subscription_title.strip(),
            "subscription_update_interval": interval,
            # Переносы строк оставляем: из них состоит текст объявления.
            "announce": announce.replace("\r\n", "\n").strip(),
            "announce_url": announce_url.strip(),
            "support_url": support_url.strip(),
        },
    )
    await log_action(
        session,
        action="settings.subscription",
        actor=admin.username,
        message="изменено оформление подписки",
        ip=request.client.host if request.client else None,
    )
    await session.commit()

    return RedirectResponse("/settings?saved=1", status_code=303)


@router.post("/settings/test-telegram")
async def test_telegram(admin: Admin = Depends(web_admin)):
    """Проверка, что уведомления настроены и доходят."""
    await notifier.send_message(
        f"✅ Проверка уведомлений из панели.\nОтправил: <b>{admin.username}</b>"
    )
    return RedirectResponse("/settings?sent=1", status_code=303)
