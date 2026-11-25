"""Проверка серверов из страны пользователей — «зонд».

Сервер в Германии сам не знает, проходит ли до него соединение из России:
блокирует не он, а ТСПУ по дороге. Поэтому проверять нужно оттуда, где
живут пользователи. Зонд — сервер в России с тем же агентом: панель
присылает ему исходящие соединения Xray ровно такие, как в подписке, и он
подключается через каждый сервер (см. /check в agent/agent.py).

Результат по каждой связке «сервер × подключение × хост»:
  ok   — туннель поднялся и через него скачался ~1 МБ;
  slow — туннель поднялся, но загрузка не прошла: соединение «замерзает»
         после первых килобайт (так в 2026 году режут подозрительный TLS);
  fail — туннель не поднялся.
Два провала подряд — сообщение в Telegram, восстановление — тоже.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import ProxyType, SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.models.probe import Probe
from app.models.user import User
from app.services import client_config, masking, notifier, probe_identity
from app.services.links import _effective_security
from app.services.node_client import NodeClient, NodeError

# Агент, который умеет /check.
PROBE_AGENT_VERSION = 8
# Сколько провалов подряд, прежде чем писать в Telegram: одиночный сбой
# бывает и у здорового сервера (перезапуск ядра, моргнула сеть).
ALERT_AFTER = 2

# Зонды, которые проверяют прямо сейчас (для страницы: «идёт проверка»).
running: set = set()
_locks: Dict[int, asyncio.Lock] = {}


def _first(value: Optional[str]) -> str:
    """Адрес и SNI в хосте могут быть списком через запятую — клиент берёт
    один из них; проверяем первый."""
    return (value or "").split(",")[0].strip()


def _set_address(outbound: Dict[str, Any], address: str) -> None:
    settings = outbound.get("settings") or {}
    for group in ("vnext", "servers"):
        for server in settings.get(group) or []:
            server["address"] = address


def build_targets(nodes: Sequence[Node], probe_user: User) -> List[Dict[str, Any]]:
    """Что проверять: каждое включённое Xray-подключение каждого включённого
    сервера — с теми же адресом, портом и SNI, что получает пользователь."""
    targets: List[Dict[str, Any]] = []
    for node in sorted(nodes, key=lambda item: (item.sort_order, item.id)):
        if not node.is_enabled:
            continue
        for inbound in sorted(node.inbounds, key=lambda item: item.id):
            if not inbound.is_enabled or inbound.protocol == ProxyType.hysteria2:
                continue
            hosts: List[Optional[Host]] = [
                host for host in inbound.hosts
                if not host.is_disabled and host.node_id in (None, node.id)
            ] or [None]
            for host in hosts:
                target = _target(node, inbound, host, probe_user)
                if target:
                    targets.append(target)
    return targets


def _target(node: Node, inbound: Inbound, host: Optional[Host], probe_user: User) -> Optional[Dict[str, Any]]:
    outbound = client_config.build_outbound(probe_user, inbound, node, host)
    if outbound is None:
        return None
    opts = inbound.settings or {}
    address = _first((host.address if host and host.address else None) or node.address)
    port = (host.port if host and host.port else None) or inbound.port
    _set_address(outbound, address)

    security = _effective_security(inbound, host)
    stream = outbound.get("streamSettings") or {}
    sni = ""
    if security == SecurityType.reality:
        # Как в ссылке подписки: свой домен сервера, иначе общий.
        sni = _first(
            (host.sni if host and host.sni else None)
            or masking.domain_for(opts, node.id)
            or node.address
        )
        stream.setdefault("realitySettings", {})["serverName"] = sni
    elif security == SecurityType.tls:
        sni = _first((stream.get("tlsSettings") or {}).get("serverName") or address)

    return {
        "key": f"{node.id}:{inbound.id}:{host.id if host else 0}",
        "outbound": outbound,
        # Рукопожатие проверяем только там, где есть TLS.
        "host": address if security != SecurityType.none else None,
        "port": port if security != SecurityType.none else None,
        "sni": sni,
        "label": {
            "node_id": node.id,
            "node": node.name,
            "country": node.country,
            "inbound": inbound.tag,
            "transport": f"{inbound.protocol.value} · {inbound.network.value} · {security.value}",
            "security": security.value,
            "sni": sni,
            "address": f"{address}:{port}",
            "host": (host.remark if host else None),
        },
    }


def classify(result: Dict[str, Any]) -> str:
    tunnel = (result.get("tunnel") or {}).get("ok")
    download = (result.get("download") or {}).get("ok")
    if tunnel and download:
        return "ok"
    if tunnel:
        return "slow"
    return "fail"


def reason(entry: Dict[str, Any]) -> str:
    """Короткое объяснение провала — для таблицы и для Telegram."""
    if entry.get("state") == "slow":
        download = entry.get("download") or {}
        return "туннель есть, но загрузка обрывается: " + (download.get("error") or "соединение замерзает")
    tls = entry.get("tls") or {}
    tunnel = entry.get("tunnel") or {}
    if tls and not tls.get("ok"):
        return f"не проходит даже TLS до сервера: {tls.get('error') or 'нет ответа'}"
    return tunnel.get("error") or "туннель не поднялся"


def merge(
    previous: Dict[str, Any], targets: Iterable[Dict[str, Any]],
    results: Iterable[Dict[str, Any]], now: str,
) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]]]:
    """Свести новый прогон с прошлым: серии провалов, «последний раз
    работало» и события для уведомлений (down/up)."""
    by_key = {item.get("key"): item for item in results}
    merged: Dict[str, Any] = {}
    events: List[Tuple[str, Dict[str, Any]]] = []
    for target in targets:
        key = target["key"]
        result = by_key.get(key) or {"tunnel": {"ok": False, "error": "зонд не вернул результат"}}
        before = previous.get(key) or {}
        state = classify(result)
        entry = dict(target["label"])
        entry.update({
            "state": state,
            "tls": result.get("tls"),
            "tunnel": result.get("tunnel"),
            "download": result.get("download"),
            "checked_at": now,
            "last_ok_at": now if state == "ok" else before.get("last_ok_at"),
            "fail_streak": 0 if state == "ok" else int(before.get("fail_streak") or 0) + 1,
            "alerted": bool(before.get("alerted")),
        })
        entry["reason"] = "" if state == "ok" else reason(entry)
        if state != "ok" and entry["fail_streak"] >= ALERT_AFTER and not entry["alerted"]:
            entry["alerted"] = True
            events.append(("down", entry))
        elif state == "ok" and entry["alerted"]:
            entry["alerted"] = False
            events.append(("up", entry))
        merged[key] = entry
    return merged, events


def alert_text(probe_name: str, events: List[Tuple[str, Dict[str, Any]]]) -> str:
    lines = []
    down = [entry for kind, entry in events if kind == "down"]
    up = [entry for kind, entry in events if kind == "up"]
    if down:
        lines.append(f"🔴 <b>Из «{probe_name}» не работает</b>")
        for entry in down:
            sni = f" · SNI {entry['sni']}" if entry.get("sni") else ""
            lines.append(f"• {entry['node']} · {entry['inbound']}{sni}\n  {entry.get('reason') or ''}")
    if up:
        if lines:
            lines.append("")
        lines.append(f"🟢 <b>Из «{probe_name}» снова работает</b>")
        for entry in up:
            lines.append(f"• {entry['node']} · {entry['inbound']}")
    return "\n".join(lines)


async def run(session: AsyncSession, probe: Probe) -> None:
    """Один прогон зонда. Ошибки самого зонда записываются в его статус."""
    from app.services.node_manager import load_nodes

    lock = _locks.setdefault(probe.id, asyncio.Lock())
    if lock.locked():
        return
    async with lock:
        running.add(probe.id)
        try:
            await _run(session, probe, load_nodes)
        finally:
            running.discard(probe.id)


async def _run(session: AsyncSession, probe: Probe, load_nodes) -> None:
    client = NodeClient(probe)
    try:
        health = await client.health()
    except NodeError as exc:
        probe.status, probe.message = "error", str(exc)
        await session.commit()
        return

    probe.agent_version = health.get("agent_version")
    probe.xray_version = health.get("xray_version") or probe.xray_version
    probe.last_seen_at = datetime.utcnow()
    if (probe.agent_version or 0) < PROBE_AGENT_VERSION:
        probe.status = "error"
        probe.message = (
            f"агент версии {probe.agent_version or '?'} не умеет проверять серверы — "
            f"нужна {PROBE_AGENT_VERSION}. Обновите его кнопкой «Обновить агента» или "
            "командой установки"
        )
        await session.commit()
        return

    identity = await probe_identity.load(session, create=True)
    targets = build_targets(await load_nodes(session), identity)
    now = datetime.utcnow().replace(microsecond=0).isoformat()
    try:
        answer = await client.check([
            {key: target[key] for key in ("key", "outbound", "host", "port", "sni")}
            for target in targets
        ]) if targets else {"results": []}
    except NodeError as exc:
        probe.status, probe.message = "error", str(exc)
        await session.commit()
        return

    # Сам маскировочный домен из этой страны: заблокированный сайт под SNI —
    # верная примета, и такой домен надо менять.
    domains = sorted({t["sni"] for t in targets if t["sni"] and t["label"]["security"] == "reality"})
    domain_results: Dict[str, Any] = {}
    if domains:
        try:
            answer_domains = await client.probe_domains(domains)
            domain_results = {
                item["domain"]: {"ok": item.get("ok"), "ms": item.get("ms"), "note": item.get("note")}
                for item in answer_domains.get("results", [])
            }
        except NodeError as exc:
            logger.warning(f"Зонд {probe.name}: проверка доменов не удалась: {exc}")

    merged, events = merge(probe.results or {}, targets, answer.get("results") or [], now)
    # Новые словари, а не правка на месте: иначе SQLAlchemy не заметит
    # изменений в JSON-колонках.
    probe.results = merged
    probe.domains = domain_results
    probe.last_run_at = datetime.utcnow()
    probe.status, probe.message = "connected", None
    await session.commit()

    bad = sum(1 for entry in merged.values() if entry["state"] != "ok")
    logger.info(f"Зонд {probe.name}: проверено {len(merged)}, не работает {bad}")
    if events:
        notifier.notify_background(alert_text(probe.name, events))


async def run_all(session: AsyncSession) -> None:
    probes = (await session.execute(select(Probe).where(Probe.is_enabled.is_(True)))).scalars().all()
    for probe in probes:
        await run(session, probe)


def run_in_background(probe_id: int) -> None:
    """«Проверить сейчас»: прогон занимает до пары минут, страницу не ждём."""
    from app.core.database import session_scope

    async def go() -> None:
        try:
            async with session_scope() as session:
                probe = await session.get(Probe, probe_id)
                if probe is not None:
                    await run(session, probe)
        except Exception as exc:  # noqa: BLE001 — фоновая задача не должна падать молча
            logger.exception(f"Зонд {probe_id}: {exc}")

    task = asyncio.get_running_loop().create_task(go())
    _pending.add(task)
    task.add_done_callback(_pending.discard)


_pending: set = set()


def summary(probe: Probe) -> Dict[str, int]:
    states = [entry.get("state") for entry in (probe.results or {}).values()]
    return {
        "total": len(states),
        "ok": states.count("ok"),
        "slow": states.count("slow"),
        "fail": states.count("fail"),
    }
