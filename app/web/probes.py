"""Зонд — сервер в стране пользователей, который проверяет остальные серверы.

Панель зонда живёт на странице «Серверы»; здесь только действия с ним.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.database import get_session
from app.models.admin import Admin
from app.models.node import Node
from app.models.probe import Probe
from app.services import probe as probe_service
from app.services import probe_identity
from app.services.agent_source import bundled_version, read_source
from app.services import bridge as bridge_service
from app.services.audit import log_action
from app.services.keys import generate_agent_token
from app.services.node_client import NodeClient, NodeError
from app.services.worker import trigger_sync

router = APIRouter(prefix="/probes")


def _back() -> RedirectResponse:
    return RedirectResponse("/nodes#probe", status_code=status.HTTP_303_SEE_OTHER)


async def _get(session: AsyncSession, probe_id: int) -> Probe:
    probe = await session.get(Probe, probe_id)
    if probe is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Зонд не найден")
    return probe


def _clean_address(value: str) -> str:
    address = value.strip().removeprefix("http://").removeprefix("https://").strip("/")
    if not address or " " in address:
        raise HTTPException(422, "Укажите адрес зонда: IP или домен")
    return address


@router.post("/create")
async def create_probe(
    request: Request,
    name: str = Form(default="Россия"),
    address: str = Form(...),
    agent_port: int = Form(default=8443),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    probe = Probe(
        name=name.strip() or "Россия",
        address=_clean_address(address),
        agent_port=agent_port or 8443,
        agent_token=generate_agent_token(),
        results={},
        domains={},
    )
    session.add(probe)
    # Ключ зонда заводим сразу: синхронизация разольёт его по серверам, и к
    # первой проверке серверы уже будут его принимать.
    await probe_identity.load(session, create=True)
    await log_action(
        session, action="probe.create", actor=admin.username, target=probe.name,
        target_type="probe", message=probe.address,
        ip=request.client.host if request.client else None,
    )
    await session.commit()
    trigger_sync()
    return _back()


@router.post("/{probe_id}/update")
async def update_probe(
    probe_id: int,
    name: str = Form(...),
    address: str = Form(...),
    agent_port: int = Form(default=8443),
    agent_tls: bool = Form(default=False),
    agent_insecure: bool = Form(default=True),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    probe = await _get(session, probe_id)
    probe.name = name.strip() or probe.name
    probe.address = _clean_address(address)
    probe.agent_port = agent_port or 8443
    probe.agent_tls = agent_tls
    probe.agent_insecure = agent_insecure
    await log_action(session, action="probe.update", actor=admin.username,
                     target=probe.name, target_type="probe")
    await session.commit()
    return _back()


@router.post("/{probe_id}/run")
async def run_probe(
    probe_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    probe = await _get(session, probe_id)
    probe_service.run_in_background(probe.id)
    return _back()


@router.post("/{probe_id}/toggle")
async def toggle_probe(
    probe_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    probe = await _get(session, probe_id)
    probe.is_enabled = not probe.is_enabled
    if not probe.is_enabled:
        await _unhide_all(session)
    await log_action(session, action="probe.toggle", actor=admin.username, target=probe.name,
                     target_type="probe", message="включён" if probe.is_enabled else "выключен")
    await session.commit()
    # Без включённого зонда его ключ уходит с серверов, и наоборот.
    trigger_sync()
    return _back()


@router.post("/{probe_id}/delete")
async def delete_probe(
    probe_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    probe = await _get(session, probe_id)
    await log_action(session, action="probe.delete", actor=admin.username,
                     target=probe.name, target_type="probe")
    await session.delete(probe)
    await _unhide_all(session)
    await session.commit()
    trigger_sync()
    return _back()


@router.post("/{probe_id}/update-agent")
async def update_probe_agent(
    probe_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    probe = await _get(session, probe_id)
    source = read_source()
    version = bundled_version(source)
    try:
        await NodeClient(probe).update_agent(source, version)
        probe.message = f"агент обновляется до версии {version} — проверка запустится сама"
        # Агент перезапускается пару секунд; потом проверка обновит версию и статус.
        probe_service.run_in_background(probe.id, delay=15)
    except NodeError as exc:
        probe.status, probe.message = "error", str(exc)
    await log_action(session, action="probe.update_agent", actor=admin.username,
                     target=probe.name, target_type="probe", message=probe.message)
    await session.commit()
    return _back()


async def _unhide_all(session: AsyncSession) -> None:
    for node in (await session.execute(select(Node).where(Node.probe_hidden.is_(True)))).scalars():
        node.probe_hidden = False


@router.post("/{probe_id}/autofix")
async def autofix_probe(
    probe_id: int,
    auto_hide: bool = Form(default=False),
    auto_port: bool = Form(default=False),
    auto_domain: bool = Form(default=False),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Что зонд исправляет сам."""
    probe = await _get(session, probe_id)
    probe.auto_hide, probe.auto_port, probe.auto_domain = auto_hide, auto_port, auto_domain
    if not auto_hide:
        # Выключили автоскрытие — всё скрытое возвращаем в подписки сразу.
        await _unhide_all(session)
    flags = [name for name, on in (("скрывать", auto_hide), ("порт", auto_port),
                                   ("домен", auto_domain)) if on]
    await log_action(session, action="probe.autofix", actor=admin.username, target=probe.name,
                     target_type="probe", message=", ".join(flags) or "всё выключено")
    await session.commit()
    return _back()


@router.post("/unhide/{node_id}")
async def unhide_node(
    node_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Вернуть сервер в подписки вручную, не дожидаясь зонда."""
    node = await session.get(Node, node_id)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    node.probe_hidden = False
    await log_action(session, action="probe.unhide", actor=admin.username, target=node.name,
                     target_type="node", message="возвращён в подписки вручную")
    await session.commit()
    return _back()


@router.post("/{probe_id}/bridge")
async def create_bridge(
    probe_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Сделать из российского сервера проверки ещё и мост: отдельный сервер в
    подписке, трафик которого уходит на рабочие иностранные серверы."""
    from app.services.node_manager import load_users, sync_node

    probe = await _get(session, probe_id)
    existing = (await session.execute(
        select(Node).where(Node.bridge.is_(True), Node.agent_token == probe.agent_token)
    )).scalars().first()
    if existing is not None:
        return _back()
    try:
        domain = await bridge_service.pick_russian_domain(probe)
    except bridge_service.BridgeError as exc:
        raise HTTPException(502, str(exc))

    name = f"{probe.name} — мост"
    taken = set((await session.execute(select(Node.name))).scalars().all())
    if name in taken:
        name = f"{name} {probe.id}"
    node = Node(
        name=name,
        address=probe.address,
        agent_host=probe.address,
        agent_port=probe.agent_port,
        agent_token=probe.agent_token,
        agent_tls=probe.agent_tls,
        agent_insecure=probe.agent_insecure,
        country="RU",
        inbounds=[],
    )
    result = await bridge_service.make_bridge(session, node, domain)
    await log_action(
        session, action="bridge.create", actor=admin.username, target=node.name,
        target_type="node",
        message=f"маскировка {domain}, порт {result['inbound'].port}, выдано: {result['granted']}",
        ip=request.client.host if request.client else None,
    )
    await session.commit()
    await session.refresh(node)
    trigger_sync()
    await sync_node(session, node, users=await load_users(session), force=True)
    return _back()
