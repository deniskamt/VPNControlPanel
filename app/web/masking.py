"""Подбор маскировки REALITY: проверка доменов с нод и свой домен у сервера.

Какой домен годится, зависит от того, откуда смотреть, поэтому проверяет
не панель, а каждая нода сама (агент, POST /probe). Результаты живут в
памяти процесса: это снимок «как было пять минут назад», а не данные,
которые стоит хранить, — после перезапуска панели проверку просто
запускают снова.
"""

import asyncio
import socket
import time
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.database import get_session
from app.models.admin import Admin
from app.models.enums import NetworkType, SecurityType
from app.models.inbound import Inbound
from app.models.node import Node
from app.services import masking, xhttp
from app.services.audit import log_action
from app.services.node_client import NodeClient, NodeError
from app.services.worker import trigger_sync
from app.web.templates import templates

router = APIRouter(prefix="/masking")

# Последняя проверка: {номер сервера: {"at": время, "results": [...], "error": ...}}
_LAST_PROBE: Dict[int, Dict[str, Any]] = {}
# Последний поиск соседей: {номер сервера: {"at", "subnet", "results", "error"}}
_LAST_NEIGHBORS: Dict[int, Dict[str, Any]] = {}


def _redirect(anchor: str = "") -> RedirectResponse:
    return RedirectResponse(
        "/masking" + (f"#{anchor}" if anchor else ""), status_code=status.HTTP_303_SEE_OTHER
    )


async def _reality_inbounds(session: AsyncSession) -> List[Inbound]:
    result = await session.execute(
        select(Inbound)
        .where(Inbound.security == SecurityType.reality)
        .order_by(Inbound.id)
    )
    return list(result.scalars().all())


def _results_by_node() -> Dict[int, List[Dict[str, Any]]]:
    return {
        node_id: probe["results"]
        for node_id, probe in _LAST_PROBE.items()
        if probe.get("results")
    }


@router.get("", response_class=HTMLResponse)
async def masking_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    nodes = list(
        (await session.execute(select(Node).order_by(Node.sort_order, Node.id)))
        .scalars()
        .all()
    )
    inbounds = await _reality_inbounds(session)

    # По каждому подключению: какие серверы, какой домен у каждого, где
    # домены совпадают.
    plans = []
    for inbound in inbounds:
        assigned = sorted(inbound.nodes, key=lambda node: (node.sort_order, node.id))
        own = masking.node_domains(inbound.settings)
        plans.append(
            {
                "inbound": inbound,
                "shared": masking.domain_for(inbound.settings, None) or "—",
                # Профиль соединений XHTTP: сколько TLS-рукопожатий видит ТСПУ.
                "xhttp_profile": (
                    xhttp.profile_of(inbound.settings or {})
                    if inbound.network == NetworkType.xhttp
                    else None
                ),
                "rows": [
                    {
                        "node": node,
                        "own": own.get(str(node.id), ""),
                        "effective": masking.domain_for(inbound.settings, node.id) or "—",
                    }
                    for node in assigned
                ],
                "duplicates": masking.duplicates(
                    inbound.settings, [node.id for node in assigned]
                ),
            }
        )

    probed_nodes = [node for node in nodes if node.id in _LAST_PROBE]
    return templates.TemplateResponse(
        request,
        "masking.html",
        {
            "admin": admin,
            "page": "inbounds",
            "nodes": nodes,
            "plans": plans,
            "catalog": masking.CATALOG,
            "all_domains": masking.ALL_DOMAINS,
            "discouraged": masking.DISCOURAGED,
            "probed_nodes": probed_nodes,
            "neighbors": [
                {
                    "node": node,
                    "found": _LAST_NEIGHBORS[node.id],
                    "usable": masking.usable_neighbors(_LAST_NEIGHBORS[node.id].get("results", [])),
                    "reality": [
                        inbound for inbound in node.inbounds
                        if inbound.security == SecurityType.reality and inbound.is_enabled
                    ],
                }
                for node in nodes
                if node.id in _LAST_NEIGHBORS
            ],
            "probe": _LAST_PROBE,
            "summary": masking.summarize(_results_by_node()),
            "node_names": {node.id: node.name for node in nodes},
            "now": time.time(),
            "xhttp_profiles": xhttp.PROFILES,
        },
    )


async def _public_ipv4(address: str) -> str:
    """Адрес ноды как IPv4 — соседей ищут по её /24."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(address, 443, family=socket.AF_INET)
    except OSError:
        return ""
    return infos[0][4][0] if infos else ""


@router.post("/neighbors")
async def find_neighbors(
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Попросить каждую ноду найти маскировочные домены среди соседей по /24.

    Пара «IP хостера + SNI сайта из того же дата-центра» выглядит обычным
    трафиком — главный совет отчётов осени 2026 (так же работает RealiTLScanner).
    """
    nodes = list(
        (await session.execute(select(Node).where(Node.is_enabled.is_(True))))
        .scalars()
        .all()
    )

    async def ask(node: Node) -> None:
        ip = await _public_ipv4(node.address)
        if not ip:
            _LAST_NEIGHBORS[node.id] = {"at": time.time(), "results": [],
                                        "error": f"не удалось узнать IPv4 по адресу {node.address}"}
            return
        try:
            answer = await NodeClient(node).neighbors(ip)
            _LAST_NEIGHBORS[node.id] = {"at": time.time(), **answer}
        except NodeError as exc:
            _LAST_NEIGHBORS[node.id] = {"at": time.time(), "results": [], "error": str(exc)}

    await asyncio.gather(*(ask(node) for node in nodes))
    await log_action(
        session,
        action="masking.neighbors",
        actor=admin.username,
        target="серверы",
        target_type="node",
        message=f"поиск соседей на {len(nodes)} серв.",
        commit=True,
    )
    return _redirect("neighbors")


@router.post("/use-neighbor")
async def use_neighbor(
    node_id: int = Form(...),
    domain: str = Form(...),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Поставить соседа маскировкой всем подключениям REALITY этого сервера."""
    value = masking.clean(domain)
    if not masking.is_valid(value):
        raise HTTPException(422, "Это не имя сайта")
    node = await session.get(Node, node_id)
    if node is None:
        raise HTTPException(404, "Сервер не найден")
    changed = []
    for inbound in await _reality_inbounds(session):
        if any(item.id == node_id for item in inbound.nodes):
            domains = masking.node_domains(inbound.settings)
            domains[str(node_id)] = value
            _save_node_domains(inbound, domains)
            changed.append(inbound.tag)
    await log_action(
        session,
        action="inbound.node_domain",
        actor=admin.username,
        target=node.name,
        target_type="node",
        message=f"сосед {value} → {', '.join(changed) or 'нет подключений REALITY'}",
        commit=True,
    )
    trigger_sync()
    return _redirect("neighbors")


@router.post("/probe")
async def run_probe(
    extra: str = Form(default=""),
    only_extra: bool = Form(default=False),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Попросить каждую включённую ноду проверить домены — параллельно."""
    custom = [masking.clean(part) for part in extra.replace(",", " ").split()]
    custom = [domain for domain in custom if masking.is_valid(domain)]
    domains = custom if (only_extra and custom) else list(
        dict.fromkeys(custom + masking.ALL_DOMAINS)
    )

    nodes = list(
        (await session.execute(select(Node).where(Node.is_enabled.is_(True))))
        .scalars()
        .all()
    )

    async def ask(node: Node) -> None:
        try:
            answer = await NodeClient(node).probe_domains(domains)
            _LAST_PROBE[node.id] = {"at": time.time(), "results": answer.get("results", [])}
        except NodeError as exc:
            _LAST_PROBE[node.id] = {"at": time.time(), "results": [], "error": str(exc)}

    await asyncio.gather(*(ask(node) for node in nodes))
    await log_action(
        session,
        action="masking.probe",
        actor=admin.username,
        target="серверы",
        target_type="node",
        message=f"доменов: {len(domains)}, серверов: {len(nodes)}",
        commit=True,
    )
    return _redirect("results")


async def _get_reality(session: AsyncSession, inbound_id: int) -> Inbound:
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None or inbound.security != SecurityType.reality:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Подключение REALITY не найдено")
    return inbound


def _save_node_domains(inbound: Inbound, domains: Dict[str, str]) -> None:
    settings = dict(inbound.settings or {})
    cleaned = {key: value for key, value in domains.items() if value}
    if cleaned:
        settings[masking.NODE_DOMAINS_KEY] = cleaned
    else:
        settings.pop(masking.NODE_DOMAINS_KEY, None)
    # Новый словарь, а не правка на месте: иначе SQLAlchemy не заметит
    # изменения в JSON-колонке и ничего не сохранит.
    inbound.settings = settings


@router.post("/{inbound_id}/node-domain")
async def set_node_domain(
    inbound_id: int,
    node_id: int = Form(...),
    domain: str = Form(default=""),
    back: str = Form(default=""),
    reset: bool = Form(default=False),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Задать (или сбросить пустым значением) домен подключения на сервере.

    Форма есть и здесь, и в «Подписке» — back возвращает туда, откуда пришли.
    """
    inbound = await _get_reality(session, inbound_id)
    value = "" if reset else masking.clean(domain)
    if value and not masking.is_valid(value):
        raise HTTPException(422, f"«{domain}» не похоже на имя сайта — нужно вроде www.example.com")

    domains = masking.node_domains(inbound.settings)
    if value:
        domains[str(node_id)] = value
    else:
        domains.pop(str(node_id), None)
    _save_node_domains(inbound, domains)

    await log_action(
        session,
        action="inbound.node_domain",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
        message=f"сервер {node_id}: {value or 'общий домен'}",
        commit=True,
    )
    trigger_sync()
    if _is_local(back):
        return RedirectResponse(back, status_code=status.HTTP_303_SEE_OTHER)
    return _redirect(f"inbound-{inbound_id}")


def _is_local(target: str) -> bool:
    """Только свои страницы: иначе форма стала бы открытым редиректом."""
    return target.startswith("/") and not target.startswith("//") and "\\" not in target


@router.post("/{inbound_id}/node-domains")
async def set_node_domains(
    inbound_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Задать домены сразу всем серверам подключения.

    Поля формы — domain_<номер сервера>; пустое значение возвращает сервер
    к общему домену подключения. Сначала проверяем всё, потом сохраняем:
    одна опечатка не должна оставлять половину серверов изменёнными.
    """
    inbound = await _get_reality(session, inbound_id)
    form = await request.form()
    allowed = {node.id for node in inbound.nodes}

    wanted: Dict[str, str] = {}
    for key, raw in form.items():
        if not key.startswith("domain_") or not key[7:].isdigit():
            continue
        node_id = int(key[7:])
        if node_id not in allowed:
            continue
        value = masking.clean(str(raw))
        if value and not masking.is_valid(value):
            raise HTTPException(
                422, f"«{raw}» не похоже на имя сайта — нужно вроде www.example.com"
            )
        wanted[str(node_id)] = value

    domains = masking.node_domains(inbound.settings)
    for node_id, value in wanted.items():
        if value:
            domains[node_id] = value
        else:
            domains.pop(node_id, None)
    _save_node_domains(inbound, domains)

    await log_action(
        session,
        action="inbound.node_domain",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
        message=f"домены на {len(wanted)} серв.",
        details={"domains": wanted},
        commit=True,
    )
    trigger_sync()
    back = str(form.get("back") or "")
    if _is_local(back):
        return RedirectResponse(back, status_code=status.HTTP_303_SEE_OTHER)
    return _redirect(f"inbound-{inbound_id}")


async def _taken_elsewhere(session: AsyncSession, inbound: Inbound) -> List[str]:
    """Домены, которые уже носят другие подключения REALITY на своих серверах."""
    taken: List[str] = []
    for other in await _reality_inbounds(session):
        if other.id == inbound.id:
            continue
        for node in other.nodes:
            domain = masking.domain_for(other.settings, node.id)
            if domain:
                taken.append(domain)
    return taken


@router.post("/{inbound_id}/auto")
async def auto_assign(
    inbound_id: int,
    back: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Раздать серверам подключения разные домены.

    Если с нод уже есть проверка — по задержке от каждого сервера. Для тех,
    по кому проверки нет, — из каталога, ближе к стране сервера. Так кнопка
    работает и до обновления агентов.
    """
    inbound = await _get_reality(session, inbound_id)
    nodes = sorted(inbound.nodes, key=lambda node: (node.sort_order, node.id))
    taken = await _taken_elsewhere(session, inbound)

    probed = {
        node_id: [item for item in results if item["domain"] not in taken]
        for node_id, results in _results_by_node().items()
    }
    neighbors = {
        node_id: [item for item in found.get("results", []) if item["domain"] not in taken]
        for node_id, found in _LAST_NEIGHBORS.items()
    }
    # Сначала соседи по подсети — самый правдоподобный вариант, потом
    # проверка с нод, потом каталог.
    chosen = masking.assign_from_neighbors([node.id for node in nodes], neighbors, taken)
    rest_ids = [node.id for node in nodes if node.id not in chosen]
    chosen.update(
        masking.assign_distinct(
            rest_ids,
            {nid: [i for i in res if i["domain"] not in chosen.values()] for nid, res in probed.items()},
        )
    )
    rest = [node for node in nodes if node.id not in chosen]
    if rest:
        chosen.update(
            masking.assign_from_catalog(
                rest, taken=list(taken) + list(chosen.values()), current=inbound.settings
            )
        )
    if not chosen:
        raise HTTPException(409, "Подключение не поднято ни на одном сервере — раздавать некому")

    domains = masking.node_domains(inbound.settings)
    for node_id, domain in chosen.items():
        domains[str(node_id)] = domain
    _save_node_domains(inbound, domains)

    await log_action(
        session,
        action="inbound.node_domain",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
        message=f"разданы разные домены на {len(chosen)} серв.",
        details={"chosen": {str(key): value for key, value in chosen.items()}},
        commit=True,
    )
    trigger_sync()
    if _is_local(back):
        return RedirectResponse(back, status_code=status.HTTP_303_SEE_OTHER)
    return _redirect(f"inbound-{inbound_id}")
