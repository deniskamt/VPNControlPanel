"""Управление серверами (нодами)."""

import asyncio
import json
from typing import List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.config import settings
from app.core.database import get_session
from app.models.admin import Admin
from app.models.enums import NodeStatus
from app.models.inbound import Inbound
from app.models.node import Node
from app.services.agent_source import bundled_version, is_outdated, read_source
from app.services.audit import log_action
from app.services.flags import country_options
from app.services.keys import generate_agent_token
from app.services.node_client import NodeClient, NodeError
from app.services.node_manager import load_users, poll_node, sync_node
from app.services.xray_config import build_node_config, config_hash
from app.services import ports, presence, xray_version
from app.web.templates import templates

router = APIRouter(prefix="/nodes")


async def _get_node(session: AsyncSession, node_id: int) -> Node:
    node = await session.get(Node, node_id)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Нода не найдена")
    return node


def _redirect() -> RedirectResponse:
    return RedirectResponse("/nodes", status_code=status.HTTP_303_SEE_OTHER)


def _clash_message(dropped, kept, agent_port) -> str:
    parts = []
    for item in dropped:
        rival = next(
            (other for other in kept if other.port == item.port
             and ports.transport(other.protocol) == ports.transport(item.protocol)),
            None,
        )
        reason = f"«{rival.tag}»" if rival else f"порт агента {agent_port}"
        parts.append(f"«{item.tag}» на порту {item.port} — там уже {reason}")
    return (
        "На одном сервере два подключения не могут делить порт: Xray не отвергает "
        "такое, а раздаёт соединения вслепую, и половина обрывается. "
        + "; ".join(parts)
        + ". Снимите одно или перенесите его на другой порт в «Подключениях»."
    )


@router.get("", response_class=HTMLResponse)
async def list_nodes(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    nodes = list(
        (await session.execute(select(Node).order_by(Node.sort_order, Node.id)))
        .scalars()
        .all()
    )
    inbounds = list(
        (await session.execute(select(Inbound).order_by(Inbound.id))).scalars().all()
    )
    agent_version = bundled_version()
    node_users = await presence.users_by_node(session)
    return templates.TemplateResponse(
        request,
        "nodes.html",
        {
            "admin": admin,
            "page": "nodes",
            "nodes": nodes,
            "inbounds": inbounds,
            "new_token": generate_agent_token(),
            # Выбор страны — общий для формы добавления и всех форм правки.
            "country_options": {
                node.id: country_options(node.country) for node in nodes
            },
            "new_country_options": country_options(),
            "panel_url": settings.PANEL_URL,
            "agent_version": agent_version,
            "agent_outdated": {
                node.id: is_outdated(node.agent_version, agent_version)
                for node in nodes
            },
            "NodeStatus": NodeStatus,
            "node_users": node_users,
            "online_counts": {
                node_id: sum(1 for row in rows if row["online"])
                for node_id, rows in node_users.items()
            },
        },
    )


@router.post("/create")
async def create_node(
    request: Request,
    name: str = Form(...),
    address: str = Form(...),
    agent_host: str = Form(default=""),
    agent_port: int = Form(default=8443),
    agent_token: str = Form(...),
    country: str = Form(default=""),
    agent_tls: bool = Form(default=False),
    agent_insecure: bool = Form(default=True),
    usage_coefficient: float = Form(default=1.0),
    inbound_ids: List[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    node = Node(
        name=name.strip(),
        address=address.strip(),
        agent_host=agent_host.strip() or None,
        agent_port=agent_port,
        agent_token=agent_token.strip(),
        agent_tls=agent_tls,
        agent_insecure=agent_insecure,
        country=country.strip() or None,
        usage_coefficient=usage_coefficient or 1.0,
        status=NodeStatus.connecting,
    )
    # Без явного выбора выдаём серверу все включённые подключения: новый
    # сервер почти всегда нужен «как остальные», а пустой список означал бы
    # ноду, на которой нечему работать.
    if inbound_ids:
        query = select(Inbound).where(Inbound.id.in_(inbound_ids))
    else:
        query = select(Inbound).where(Inbound.is_enabled.is_(True))
    chosen = list((await session.execute(query)).scalars().all())
    # Два подключения на одном порту Xray делит вслепую — половина соединений
    # уходит не туда (services/ports.py). Выбранное руками — отказ с
    # объяснением; выбранное «по умолчанию» — без лишних, с записью в журнал.
    kept, dropped = ports.split_clashing(chosen, agent_port)
    if dropped and inbound_ids:
        raise HTTPException(422, _clash_message(dropped, kept, agent_port))
    node.inbounds = kept

    session.add(node)
    if dropped:
        await log_action(
            session,
            action="node.create",
            actor=admin.username,
            target=node.name,
            target_type="node",
            level="warning",
            message="не подняты из-за занятого порта: "
            + ", ".join(f"«{item.tag}» ({item.port})" for item in dropped),
        )
    await log_action(
        session,
        action="node.create",
        actor=admin.username,
        target=node.name,
        target_type="node",
        ip=request.client.host if request.client else None,
    )
    await session.commit()
    await session.refresh(node)

    # Сразу заливаем конфиг, чтобы нода начала работать без ожидания цикла.
    await sync_node(session, node, users=await load_users(session), force=True)
    return _redirect()


@router.post("/{node_id}/update")
async def update_node(
    node_id: int,
    request: Request,
    name: str = Form(...),
    address: str = Form(...),
    agent_host: str = Form(default=""),
    agent_port: int = Form(default=8443),
    agent_token: str = Form(default=""),
    country: str = Form(default=""),
    agent_tls: bool = Form(default=False),
    agent_insecure: bool = Form(default=True),
    usage_coefficient: float = Form(default=1.0),
    inbound_ids: List[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    node = await _get_node(session, node_id)
    node.name = name.strip()
    node.address = address.strip()
    node.agent_host = agent_host.strip() or None
    node.agent_port = agent_port
    node.agent_tls = agent_tls
    node.agent_insecure = agent_insecure
    node.country = country.strip() or None
    node.usage_coefficient = usage_coefficient or 1.0
    if agent_token.strip():
        node.agent_token = agent_token.strip()

    result = await session.execute(select(Inbound).where(Inbound.id.in_(inbound_ids or [])))
    chosen = list(result.scalars().all())
    # Отказываем только за новый конфликт: уже существующий (собранный до
    # этой проверки) не должен мешать, скажем, переименовать сервер — его
    # покажет «Требует внимания» с кнопкой переноса.
    before = {item.id for item in node.inbounds}
    kept, dropped = ports.split_clashing(chosen, node.agent_port)
    fresh = [item for item in dropped if item.id not in before]
    if fresh:
        raise HTTPException(422, _clash_message(fresh, kept, node.agent_port))
    node.inbounds = chosen
    # Адрес/набор inbound'ов изменились — конфиг надо перезалить.
    node.config_hash = None

    await log_action(
        session,
        action="node.update",
        actor=admin.username,
        target=node.name,
        target_type="node",
        ip=request.client.host if request.client else None,
    )
    await session.commit()
    await session.refresh(node)

    await sync_node(session, node, users=await load_users(session), force=True)
    return _redirect()


@router.post("/{node_id}/toggle")
async def toggle_node(
    node_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    node = await _get_node(session, node_id)
    node.is_enabled = not node.is_enabled
    node.status = NodeStatus.connecting if node.is_enabled else NodeStatus.disabled
    await log_action(
        session,
        action="node.toggle",
        actor=admin.username,
        target=node.name,
        target_type="node",
        message="включена" if node.is_enabled else "выключена",
    )
    await session.commit()
    return _redirect()


@router.post("/{node_id}/sync")
async def sync_node_now(
    node_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    node = await _get_node(session, node_id)
    await sync_node(session, node, users=await load_users(session), force=True)
    await log_action(
        session,
        action="node.sync",
        actor=admin.username,
        target=node.name,
        target_type="node",
        commit=True,
    )
    return _redirect()


@router.post("/{node_id}/restart")
async def restart_node(
    node_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    node = await _get_node(session, node_id)
    try:
        await NodeClient(node).restart()
        message: Optional[str] = None
        level = "info"
    except NodeError as exc:
        message = str(exc)
        level = "error"

    await log_action(
        session,
        action="node.restart",
        actor=admin.username,
        target=node.name,
        target_type="node",
        message=message,
        level=level,
        commit=True,
    )
    await poll_node(session, node)
    return _redirect()


@router.post("/update-xray")
async def update_all_xray(
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Поставить рекомендуемое ядро Xray на все серверы, где оно старее.

    Агент сам скачивает ядро, проверяет им текущий конфиг и откатывается,
    если новое не поднялось, — нода без Xray не останется.
    """
    target = xray_version.RECOMMENDED
    nodes = [
        node
        for node in (await session.execute(select(Node).where(Node.is_enabled.is_(True))))
        .scalars()
        .all()
        if xray_version.is_outdated(node.xray_version)
    ]

    async def one(node: Node):
        try:
            return await NodeClient(node).update_xray(target)
        except NodeError as exc:
            return exc

    answers = await asyncio.gather(*(one(node) for node in nodes))
    failed = []
    for node, answer in zip(nodes, answers):
        if isinstance(answer, NodeError):
            failed.append(f"{node.name}: {answer}")
        else:
            node.xray_version = answer.get("xray_version") or node.xray_version

    await log_action(
        session,
        action="node.update_xray",
        actor=admin.username,
        target="все серверы",
        target_type="node",
        level="error" if failed else "info",
        message=(
            f"Xray {target}: {len(nodes) - len(failed)} из {len(nodes)}"
            + (f"; не вышло — {'; '.join(failed)}" if failed else "")
        ),
    )
    await session.commit()
    return _redirect()


@router.post("/update-agents")
async def update_all_agents(
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Обновить агента на всех серверах, где он устарел, — разом.

    После обновления панели устаревают все агенты сразу, и кнопка на каждом
    сервере по очереди превращалась в девять одинаковых нажатий.
    """
    source = read_source()
    version = bundled_version(source)
    nodes = [
        node
        for node in (await session.execute(select(Node).where(Node.is_enabled.is_(True))))
        .scalars()
        .all()
        if is_outdated(node.agent_version, version)
    ]

    async def one(node: Node) -> Optional[str]:
        try:
            await NodeClient(node).update_agent(source, version)
            return None
        except NodeError as exc:
            return str(exc)

    errors = await asyncio.gather(*(one(node) for node in nodes))
    failed = []
    for node, error in zip(nodes, errors):
        if error:
            node.status = NodeStatus.error
            node.message = error
            failed.append(node.name)
        else:
            # Агент выйдет и поднимется через systemd — несколько секунд.
            node.agent_version = version
            node.status = NodeStatus.connecting
            node.message = None

    await log_action(
        session,
        action="node.update_agent",
        actor=admin.username,
        target="все серверы",
        target_type="node",
        level="error" if failed else "info",
        message=(
            f"обновлено до версии {version}: {len(nodes) - len(failed)} из {len(nodes)}"
            + (f"; не вышло: {', '.join(failed)}" if failed else "")
        ),
    )
    await session.commit()
    return _redirect()


@router.post("/{node_id}/update-agent")
async def update_agent(
    node_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Разослать ноде свежий код агента.

    Ходить по серверам с ssh после каждого обновления панели — верный способ
    оставить на нодах старого агента. Канал к агенту уже есть, код лежит
    рядом с панелью, так что обновление — это одна кнопка.
    """
    node = await _get_node(session, node_id)
    source = read_source()
    version = bundled_version(source)

    try:
        await NodeClient(node).update_agent(source, version)
        message: Optional[str] = f"агент обновлён до версии {version}"
        level = "info"
    except NodeError as exc:
        message = str(exc)
        level = "error"

    await log_action(
        session,
        action="node.update_agent",
        actor=admin.username,
        target=node.name,
        target_type="node",
        message=message,
        level=level,
        commit=True,
    )

    if level == "error":
        node.status = NodeStatus.error
        node.message = message
        await session.commit()
    else:
        # Агент выйдет и поднимется через systemd — на это нужно несколько
        # секунд, и до них опрашивать его бессмысленно.
        node.agent_version = version
        node.status = NodeStatus.connecting
        node.message = None
        await session.commit()

    return _redirect()


@router.get("/{node_id}/config", response_class=HTMLResponse)
async def node_config(
    node_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Конфиг Xray, который панель держит на этом сервере.

    Смотреть его вручную не нужно — панель собирает и заливает конфиг сама,
    но при разборе неполадок полезно видеть, что именно уехало на ноду.
    """
    node = await _get_node(session, node_id)
    users = await load_users(session)
    config = build_node_config(node, users)

    return templates.TemplateResponse(
        request,
        "node_config.html",
        {
            "admin": admin,
            "page": "nodes",
            "node": node,
            "config": json.dumps(config, indent=2, ensure_ascii=False),
            "config_hash": config_hash(config),
            "applied_hash": node.config_hash,
            "clients": sum(
                len((inbound.get("settings") or {}).get("clients") or [])
                for inbound in config["inbounds"]
            ),
        },
    )


@router.post("/{node_id}/delete")
async def delete_node(
    node_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    node = await _get_node(session, node_id)
    name = node.name
    await session.delete(node)
    await log_action(
        session,
        action="node.delete",
        actor=admin.username,
        target=name,
        target_type="node",
        level="warning",
    )
    await session.commit()
    return _redirect()
