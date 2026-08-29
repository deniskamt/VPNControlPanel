"""Раздел «Подписка»: что увидит пользователь и как это настроить.

Страница отвечает на вопрос, который иначе выясняется перебором: какие
конфигурации попадут человеку в приложение, как они будут называться и куда
пойдут. Каждую строку можно настроить, не уходя со страницы, — под этим
лежат те же «хосты», что и раньше, но теперь их не нужно собирать в голове.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.config import settings
from app.core.database import get_session
from app.models.admin import Admin
from app.models.enums import SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.models.user import User
from app.services import links, settings_store, subscription_view
from app.services import users as user_service
from app.services.audit import log_action
from app.services.worker import trigger_sync
from app.web.templates import templates

router = APIRouter(prefix="/subscription")

# Плейсхолдеры для названия конфигурации — их подставляет панель.
REMARK_TOKENS = [
    ("{flag}", "флаг страны сервера"),
    ("{node}", "название сервера"),
    ("{country}", "код страны"),
    ("{protocol}", "протокол (vless, trojan…)"),
    ("{tag}", "имя подключения"),
    ("{username}", "имя пользователя"),
]


def _redirect(user_id: Optional[int] = None) -> RedirectResponse:
    target = "/subscription" + (f"?user_id={user_id}" if user_id else "")
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


async def _preview_user(session: AsyncSession, user_id: Optional[int]) -> Optional[User]:
    """Пользователь, на котором показываем предпросмотр."""
    if user_id:
        user = await session.get(User, user_id)
        if user:
            return user
    result = await session.execute(select(User).order_by(User.id).limit(1))
    return result.scalar_one_or_none()


@router.get("", response_class=HTMLResponse)
async def subscription_page(
    request: Request,
    user_id: Optional[int] = Query(default=None),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    users = list(
        (await session.execute(select(User).order_by(User.username).limit(500)))
        .scalars()
        .all()
    )
    nodes = list(
        (await session.execute(select(Node).order_by(Node.sort_order, Node.id)))
        .scalars()
        .all()
    )
    inbounds = list(
        (await session.execute(select(Inbound).order_by(Inbound.id))).scalars().all()
    )

    user = await _preview_user(session, user_id)
    entries = subscription_view.entries_for(user, nodes) if user else []
    hidden = subscription_view.hidden_entries(user, nodes) if user else []

    return templates.TemplateResponse(
        request,
        "subscription.html",
        {
            "admin": admin,
            "page": "subscription",
            "users": users,
            "nodes": nodes,
            "inbounds": inbounds,
            "user": user,
            "entries": entries,
            "hidden": hidden,
            "securities": [item.value for item in SecurityType],
            "remark_tokens": REMARK_TOKENS,
            "options": await settings_store.get_all(session),
            "subscription_url": (
                settings.subscription_url(user_service.subscription_token(user))
                if user
                else ""
            ),
        },
    )


@router.post("/hosts/create")
async def create_host(
    inbound_id: int = Form(...),
    node_id: str = Form(default=""),
    remark: str = Form(default="{flag} {node}"),
    address: str = Form(default=""),
    port: str = Form(default=""),
    sni: str = Form(default=""),
    host_header: str = Form(default="", alias="host"),
    path: str = Form(default=""),
    security: str = Form(default=""),
    alpn: str = Form(default=""),
    fingerprint: str = Form(default=""),
    allowinsecure: bool = Form(default=False),
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Подключение не найдено")

    host = Host(
        inbound_id=inbound_id,
        node_id=int(node_id) if node_id.strip().isdigit() else None,
        remark=remark.strip() or "{flag} {node}",
        address=address.strip() or None,
        port=int(port) if port.strip().isdigit() else None,
        sni=sni.strip() or None,
        host=host_header.strip() or None,
        path=path.strip() or None,
        security=SecurityType(security) if security.strip() else None,
        alpn=alpn.strip() or None,
        fingerprint=fingerprint.strip() or None,
        allowinsecure=allowinsecure,
    )
    session.add(host)
    await log_action(
        session,
        action="host.create",
        actor=admin.username,
        target=inbound.tag,
        target_type="host",
        message=f"название «{host.remark}»",
    )
    await session.commit()
    return _redirect(int(user_id) if user_id.strip().isdigit() else None)


@router.post("/hosts/{host_id}/update")
async def update_host(
    host_id: int,
    remark: str = Form(default="{flag} {node}"),
    address: str = Form(default=""),
    port: str = Form(default=""),
    sni: str = Form(default=""),
    host_header: str = Form(default="", alias="host"),
    path: str = Form(default=""),
    security: str = Form(default=""),
    alpn: str = Form(default=""),
    fingerprint: str = Form(default=""),
    allowinsecure: bool = Form(default=False),
    sort_order: int = Form(default=0),
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    host = await session.get(Host, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Хост не найден")

    host.remark = remark.strip() or "{flag} {node}"
    host.address = address.strip() or None
    host.port = int(port) if port.strip().isdigit() else None
    host.sni = sni.strip() or None
    host.host = host_header.strip() or None
    host.path = path.strip() or None
    host.security = SecurityType(security) if security.strip() else None
    host.alpn = alpn.strip() or None
    host.fingerprint = fingerprint.strip() or None
    host.allowinsecure = allowinsecure
    host.sort_order = sort_order

    await log_action(
        session,
        action="host.update",
        actor=admin.username,
        target=str(host_id),
        target_type="host",
        commit=True,
    )
    return _redirect(int(user_id) if user_id.strip().isdigit() else None)


@router.post("/hosts/{host_id}/toggle")
async def toggle_host(
    host_id: int,
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    host = await session.get(Host, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Хост не найден")
    host.is_disabled = not host.is_disabled
    await log_action(
        session,
        action="host.toggle",
        actor=admin.username,
        target=str(host_id),
        target_type="host",
        message="скрыт из подписки" if host.is_disabled else "снова в подписке",
        commit=True,
    )
    return _redirect(int(user_id) if user_id.strip().isdigit() else None)


@router.post("/hosts/{host_id}/delete")
async def delete_host(
    host_id: int,
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    host = await session.get(Host, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Хост не найден")
    await session.delete(host)
    await log_action(
        session,
        action="host.delete",
        actor=admin.username,
        target=str(host_id),
        target_type="host",
        level="warning",
    )
    await session.commit()
    return _redirect(int(user_id) if user_id.strip().isdigit() else None)


@router.post("/rows/move")
async def move_row(
    direction: str = Form(...),
    node_id: int = Form(...),
    inbound_id: int = Form(...),
    host_id: int = Form(default=0),
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Поднять или опустить одну строку подписки.

    Порядок сквозной: строку можно поставить между записями другого сервера.
    У строки «по умолчанию» своего места нет — она наследует его от сервера,
    поэтому при первом же перемещении для неё заводится хост без каких-либо
    переопределений. На вид ссылка от этого не меняется.
    """
    preview = int(user_id) if user_id.strip().isdigit() else None
    user = await _preview_user(session, preview)
    if user is None:
        return _redirect(preview)

    nodes = list((await session.execute(select(Node))).scalars().all())
    rows = links.user_rows(user, nodes)
    index = next(
        (
            position
            for position, (node, inbound, host) in enumerate(rows)
            if node.id == node_id
            and inbound.id == inbound_id
            and (host.id if host else 0) == host_id
        ),
        None,
    )
    if index is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Строка не найдена")

    target = index - 1 if direction == "up" else index + 1
    if 0 <= target < len(rows):
        node, inbound, host = rows[index]
        if host is None:
            host = Host(
                inbound_id=inbound.id, node_id=node.id, remark=links.DEFAULT_REMARK
            )
            session.add(host)
            await session.flush()
            rows[index] = (node, inbound, host)

        rows[index], rows[target] = rows[target], rows[index]
        subscription_view.apply_order(rows)
        await log_action(
            session,
            action="subscription.move",
            actor=admin.username,
            target=f"{node.name} → {inbound.tag}",
            target_type="host",
            message="выше в подписке" if direction == "up" else "ниже в подписке",
        )

    await session.commit()
    return _redirect(preview)


@router.post("/nodes/{node_id}/inbounds/{inbound_id}/detach")
async def detach_inbound(
    node_id: int,
    inbound_id: int,
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Убрать подключение с одного сервера.

    Ничего не удаляется: само подключение, его параметры и настройки строк
    остаются на месте, меняется только список серверов, где оно поднимается.
    Вернуть обратно — галочкой в таблице «Какие протоколы на каких серверах».
    """
    node = await session.get(Node, node_id)
    inbound = await session.get(Inbound, inbound_id)
    if node is None or inbound is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер или подключение не найдены")

    node.inbounds = [item for item in node.inbounds if item.id != inbound_id]
    await log_action(
        session,
        action="node.inbounds",
        actor=admin.username,
        target=node.name,
        target_type="node",
        message=f"«{inbound.tag}» убрано с сервера",
        commit=True,
    )
    trigger_sync()
    return _redirect(int(user_id) if user_id.strip().isdigit() else None)


def _numbers(values: List[str]) -> set:
    """Числа из полей формы — всё остальное молча отбрасываем."""
    return {int(value) for value in values if value.strip().isdigit()}


@router.post("/nodes/inbounds")
async def save_node_inbounds(
    pair: List[str] = Form(default=[]),
    node: List[str] = Form(default=[]),
    column: List[str] = Form(default=[]),
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Сохранить таблицу «какой протокол на каком сервере».

    Браузер присылает только отмеченные клетки, поэтому снятую галочку иначе
    не отличить от строки, которой на странице не было. Вместе с клетками
    форма присылает и свои строки со столбцами — за их пределами ничего не
    трогаем: сервер или подключение, добавленные после открытия страницы, не
    должны пропасть от чужого сохранения.

    Меняются только связи. Ни подключения, ни их параметры, ни настройки
    строк, ни ключи пользователей отсюда не удаляются.
    """
    checked = set()
    for item in pair:
        left, _, right = item.partition(":")
        if left.strip().isdigit() and right.strip().isdigit():
            checked.add((int(left), int(right)))

    shown_nodes = _numbers(node)
    shown_inbounds = _numbers(column)

    nodes = list(
        (await session.execute(select(Node).where(Node.id.in_(shown_nodes))))
        .scalars()
        .all()
    )
    inbounds = {
        item.id: item
        for item in (
            await session.execute(select(Inbound).where(Inbound.id.in_(shown_inbounds)))
        )
        .scalars()
        .all()
    }

    changes: List[str] = []
    for item in nodes:
        was = {inbound.id for inbound in item.inbounds}
        # За пределами показанных столбцов оставляем всё как было.
        now = (was - set(inbounds)) | {
            inbound_id
            for node_id, inbound_id in checked
            if node_id == item.id and inbound_id in inbounds
        }
        if was == now:
            continue
        by_id = {inbound.id: inbound for inbound in item.inbounds} | inbounds
        item.inbounds = [by_id[inbound_id] for inbound_id in sorted(now)]
        for inbound_id in sorted(was - now):
            changes.append(f"{item.name}: убрано «{by_id[inbound_id].tag}»")
        for inbound_id in sorted(now - was):
            changes.append(f"{item.name}: добавлено «{by_id[inbound_id].tag}»")

    if changes:
        await log_action(
            session,
            action="node.inbounds",
            actor=admin.username,
            target="серверы",
            target_type="node",
            message="; ".join(changes),
        )
    await session.commit()
    if changes:
        trigger_sync()
    return _redirect(int(user_id) if user_id.strip().isdigit() else None)


@router.post("/inbounds/{inbound_id}/toggle")
async def toggle_inbound(
    inbound_id: int,
    user_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Выключить подключение целиком — оно исчезнет у всех пользователей."""
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Подключение не найдено")
    inbound.is_enabled = not inbound.is_enabled
    await log_action(
        session,
        action="inbound.toggle",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
        message="включено" if inbound.is_enabled else "выключено",
        commit=True,
    )
    trigger_sync()
    return _redirect(int(user_id) if user_id.strip().isdigit() else None)
