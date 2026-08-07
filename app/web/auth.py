"""Вход и выход из веб-панели."""

from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.security import verify_password
from app.models.admin import Admin
from app.services.audit import log_action
from app.web.templates import templates

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str = "/"):
    if request.session.get("admin"):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request, "login.html", {"next": next, "error": None}
    )


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(default="/"),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Admin).where(Admin.username == username, Admin.is_active.is_(True))
    )
    admin = result.scalar_one_or_none()

    if admin is None or not verify_password(password, admin.hashed_password):
        await log_action(
            session,
            action="admin.login_failed",
            actor=username or "?",
            level="warning",
            ip=request.client.host if request.client else None,
            commit=True,
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            {"next": next, "error": "Неверный логин или пароль"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    admin.last_login_at = datetime.utcnow()
    request.session["admin"] = admin.username
    await log_action(
        session,
        action="admin.login",
        actor=admin.username,
        ip=request.client.host if request.client else None,
    )
    await session.commit()

    return RedirectResponse(next or "/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
