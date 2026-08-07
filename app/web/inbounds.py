"""Настройка входящих подключений Xray (inbound'ов) и их хостов."""

import json
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.database import get_session
from app.models.admin import Admin
from app.models.enums import NetworkType, ProxyType, SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.services import presets as preset_service
from app.services.audit import log_action
from app.services.worker import trigger_sync
from app.web.templates import templates

router = APIRouter(prefix="/inbounds")


def _parse_settings(raw: str) -> Dict[str, Any]:
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(422, f"Параметры должны быть корректным JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(422, "Параметры должны быть JSON-объектом")
    return parsed


def _redirect() -> RedirectResponse:
    return RedirectResponse("/inbounds", status_code=status.HTTP_303_SEE_OTHER)


async def _get_inbound(session: AsyncSession, inbound_id: int) -> Inbound:
    inbound = await session.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Inbound не найден")
    return inbound


@router.get("", response_class=HTMLResponse)
async def list_inbounds(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    inbounds = list(
        (await session.execute(select(Inbound).order_by(Inbound.id))).scalars().all()
    )
    nodes = list(
        (await session.execute(select(Node).order_by(Node.sort_order, Node.id)))
        .scalars()
        .all()
    )

    return templates.TemplateResponse(
        request,
        "inbounds.html",
        {
            "admin": admin,
            "page": "inbounds",
            "inbounds": inbounds,
            "nodes": nodes,
            "protocols": [item.value for item in ProxyType],
            "networks": [item.value for item in NetworkType],
            "securities": [item.value for item in SecurityType],
            "presets": preset_service.PRESETS,
            "masking_domains": preset_service.MASKING_DOMAINS,
            "settings_json": {
                inbound.id: json.dumps(
                    inbound.settings or {}, ensure_ascii=False, indent=2
                )
                for inbound in inbounds
            },
        },
    )


@router.post("/quick")
async def quick_create(
    preset: str = Form(...),
    port: int = Form(0),
    masking_domain: str = Form(default=""),
    sni: str = Form(default=""),
    certificate_file: str = Form(default=""),
    key_file: str = Form(default=""),
    node_ids: List[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Создать подключение по шаблону: без JSON и без похода на сервер за ключами."""
    template = preset_service.PRESETS_BY_KEY.get(preset)
    if template is None:
        raise HTTPException(422, f"Неизвестный шаблон: {preset}")

    existing = list(
        (await session.execute(select(Inbound.tag))).scalars().all()
    )
    tag = preset_service.suggest_tag(template, existing)

    inbound = Inbound(
        tag=tag,
        remark=template.title,
        protocol=template.protocol,
        port=port or template.default_port,
        network=template.network,
        security=template.security,
        listen="0.0.0.0",
        settings=preset_service.build_settings(
            template,
            masking_domain=masking_domain,
            certificate_file=certificate_file,
            key_file=key_file,
            sni=sni,
        ),
    )

    # По умолчанию поднимаем подключение на всех серверах: держать его
    # включённым, но ни к одному серверу не привязанным, смысла нет.
    if node_ids:
        result = await session.execute(select(Node).where(Node.id.in_(node_ids)))
    else:
        result = await session.execute(select(Node).where(Node.is_enabled.is_(True)))
    inbound.nodes = list(result.scalars().all())

    session.add(inbound)
    await log_action(
        session,
        action="inbound.create",
        actor=admin.username,
        target=tag,
        target_type="inbound",
        message=f"по шаблону «{template.title}»",
    )
    await session.commit()

    trigger_sync()
    return _redirect()


@router.post("/create")
async def create_inbound(
    tag: str = Form(...),
    protocol: str = Form(...),
    port: int = Form(...),
    network: str = Form(default="tcp"),
    security: str = Form(default="none"),
    listen: str = Form(default="0.0.0.0"),
    remark: str = Form(default=""),
    settings_raw: str = Form(default="", alias="settings"),
    node_ids: List[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    existing = await session.execute(select(Inbound).where(Inbound.tag == tag.strip()))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Inbound с таким tag уже есть")

    inbound = Inbound(
        tag=tag.strip(),
        remark=remark.strip() or None,
        protocol=ProxyType(protocol),
        port=port,
        network=NetworkType(network),
        security=SecurityType(security),
        listen=listen.strip() or "0.0.0.0",
        settings=_parse_settings(settings_raw),
    )
    if node_ids:
        result = await session.execute(select(Node).where(Node.id.in_(node_ids)))
        inbound.nodes = list(result.scalars().all())

    session.add(inbound)
    await log_action(
        session,
        action="inbound.create",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
    )
    await session.commit()

    trigger_sync()
    return _redirect()


@router.post("/{inbound_id}/update")
async def update_inbound(
    inbound_id: int,
    tag: str = Form(...),
    protocol: str = Form(...),
    port: int = Form(...),
    network: str = Form(default="tcp"),
    security: str = Form(default="none"),
    listen: str = Form(default="0.0.0.0"),
    remark: str = Form(default=""),
    settings_raw: str = Form(default="", alias="settings"),
    node_ids: List[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    inbound = await _get_inbound(session, inbound_id)
    inbound.tag = tag.strip()
    inbound.remark = remark.strip() or None
    inbound.protocol = ProxyType(protocol)
    inbound.port = port
    inbound.network = NetworkType(network)
    inbound.security = SecurityType(security)
    inbound.listen = listen.strip() or "0.0.0.0"
    inbound.settings = _parse_settings(settings_raw)

    result = await session.execute(select(Node).where(Node.id.in_(node_ids or [])))
    inbound.nodes = list(result.scalars().all())

    await log_action(
        session,
        action="inbound.update",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
    )
    await session.commit()

    trigger_sync()
    return _redirect()


@router.post("/{inbound_id}/toggle")
async def toggle_inbound(
    inbound_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    inbound = await _get_inbound(session, inbound_id)
    inbound.is_enabled = not inbound.is_enabled
    await log_action(
        session,
        action="inbound.toggle",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
        message="включён" if inbound.is_enabled else "выключен",
    )
    await session.commit()

    trigger_sync()
    return _redirect()


@router.post("/{inbound_id}/delete")
async def delete_inbound(
    inbound_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    inbound = await _get_inbound(session, inbound_id)
    tag = inbound.tag
    await session.delete(inbound)
    await log_action(
        session,
        action="inbound.delete",
        actor=admin.username,
        target=tag,
        target_type="inbound",
        level="warning",
    )
    await session.commit()

    trigger_sync()
    return _redirect()


@router.post("/{inbound_id}/hosts/create")
async def create_host(
    inbound_id: int,
    remark: str = Form(default="{node}"),
    address: str = Form(default=""),
    port: str = Form(default=""),
    sni: str = Form(default=""),
    host_header: str = Form(default="", alias="host"),
    path: str = Form(default=""),
    alpn: str = Form(default=""),
    fingerprint: str = Form(default=""),
    security: str = Form(default=""),
    allowinsecure: bool = Form(default=False),
    node_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    inbound = await _get_inbound(session, inbound_id)
    session.add(
        Host(
            security=SecurityType(security) if security else None,
            inbound_id=inbound.id,
            remark=remark.strip() or "{node}",
            address=address.strip() or None,
            port=int(port) if port.strip().isdigit() else None,
            sni=sni.strip() or None,
            host=host_header.strip() or None,
            path=path.strip() or None,
            alpn=alpn.strip() or None,
            fingerprint=fingerprint.strip() or None,
            allowinsecure=allowinsecure,
            node_id=int(node_id) if node_id.strip().isdigit() else None,
        )
    )
    await log_action(
        session,
        action="host.create",
        actor=admin.username,
        target=inbound.tag,
        target_type="inbound",
    )
    await session.commit()
    return _redirect()


@router.post("/hosts/{host_id}/delete")
async def delete_host(
    host_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    host = await session.get(Host, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Host не найден")
    await session.delete(host)
    await log_action(
        session,
        action="host.delete",
        actor=admin.username,
        target=str(host_id),
        target_type="host",
    )
    await session.commit()
    return _redirect()
