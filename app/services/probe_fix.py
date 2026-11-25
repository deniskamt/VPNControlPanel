"""Самолечение по результатам зонда.

Зонд видит из России, что не работает; здесь решается, что из этого панель
может исправить сама, и исправляется. Три вида поломок различаются так:

  порт режут   — до одного порта сервера из России не доходит даже TCP, а из
                 Европы доходит, и другие порты того же сервера из России
                 открыты. Лечится переносом подключения на другой порт.
  домен режут  — рукопожатие проходит, а данные нет (туннель не поднимается
                 или «замерзает»). Так ТСПУ режет по SNI. Лечится сменой
                 маскировочного домена у этого сервера.
  IP заблокирован — из России не доходит ничего, из Европы сервер жив.
                 Это не лечится: нужен новый IP у хостинга. Панель на время
                 убирает сервер из подписок, чтобы люди не натыкались на
                 мёртвый сервер, и возвращает, как только он заработает.

Решение (plan) отделено от исполнения (apply): первое — чистая функция и
проверяется тестами, второе ходит в сеть и меняет базу.
"""

from __future__ import annotations

import asyncio
import math
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from loguru import logger

from app.models.enums import NodeStatus, ProxyType, SecurityType
from app.services import masking, ports

# Подтверждённая поломка — столько провалов подряд (как для уведомлений).
CONFIRM_AFTER = 2
# Не дёргать порт подключения чаще: каждая смена — обновление подписок.
PORT_COOLDOWN = timedelta(hours=6)
# Домен сервера: не чаще раза в 20 минут и не больше трёх раз в сутки.
DOMAIN_COOLDOWN = timedelta(minutes=20)
DOMAIN_DAILY_LIMIT = 3
# Сколько кандидатов в домены проверять из России за раз.
DOMAIN_CANDIDATES = 10
# Сколько записей «что сделал зонд» хранить.
LOG_SIZE = 30
# Перепроверка после исправления: дать серверам время принять конфиг.
RECHECK_DELAY = 180


@dataclass
class NodeView:
    node_id: int
    name: str
    entries: List[Dict[str, Any]]
    any_ok: bool = False          # хоть что-то на сервере доходит из России
    ip_blocked: bool = False      # из России не доходит ничего, из Европы жив
    dead: bool = False            # не доходит ни оттуда, ни отсюда


@dataclass
class Plan:
    hide: List[int] = field(default_factory=list)
    unhide: List[int] = field(default_factory=list)
    # (подключение, серверы, до которых из России вообще что-то доходит)
    move_ports: List[Tuple[int, List[int]]] = field(default_factory=list)
    rotate_domains: List[Tuple[int, str]] = field(default_factory=list)  # (сервер, домен)
    notes: Dict[str, str] = field(default_factory=dict)            # ключ → текст
    # Выставляет apply: поменялся конфиг серверов (порт или домен).
    config_changed: bool = False

    @property
    def empty(self) -> bool:
        return not (self.hide or self.unhide or self.move_ports or self.rotate_domains)


def _split(key: str) -> Tuple[int, int]:
    node_id, inbound_id, _ = (key.split(":") + ["0", "0"])[:3]
    return int(node_id), int(inbound_id)


def _confirmed(entry: Dict[str, Any]) -> bool:
    return entry.get("state") != "ok" and int(entry.get("fail_streak") or 0) >= CONFIRM_AFTER


def _tls(entry: Dict[str, Any]) -> Dict[str, Any]:
    return entry.get("tls") or {}


def _control_ok(entry: Dict[str, Any]) -> bool:
    return bool((entry.get("control") or {}).get("ok"))


def _reaches(entry: Dict[str, Any]) -> bool:
    """Из России до сервера что-то доходит по этой связке."""
    return entry.get("state") == "ok" or bool(_tls(entry).get("ok")) or bool(
        (entry.get("tunnel") or {}).get("ok")
    )


def node_views(merged: Dict[str, Any]) -> Dict[int, NodeView]:
    views: Dict[int, NodeView] = {}
    for key, entry in merged.items():
        node_id, inbound_id = _split(key)
        item = dict(entry, key=key, node_id=node_id, inbound_id=inbound_id)
        view = views.setdefault(node_id, NodeView(node_id, entry.get("node") or str(node_id), []))
        view.entries.append(item)
    for view in views.values():
        view.any_ok = any(_reaches(entry) for entry in view.entries)
        if view.any_ok or not all(_confirmed(entry) for entry in view.entries):
            continue
        with_control = [entry for entry in view.entries if entry.get("control")]
        if any(_control_ok(entry) for entry in with_control):
            view.ip_blocked = True
        elif with_control:
            view.dead = True
    return views


def plan(
    nodes: Sequence[Any],
    merged: Dict[str, Any],
    history: Dict[str, Any],
    *,
    auto_hide: bool = True,
    auto_port: bool = True,
    auto_domain: bool = True,
    now: Optional[datetime] = None,
) -> Plan:
    """Что исправлять по результатам последнего прогона."""
    now = now or datetime.utcnow()
    result = Plan()
    views = node_views(merged)
    by_id = {node.id: node for node in nodes}
    enabled = [node for node in nodes if node.is_enabled]

    # --- IP заблокирован: убрать из подписок, вернуть, когда оживёт ----------
    blocked = [view for view in views.values() if view.ip_blocked and view.node_id in by_id]
    for view in views.values():
        node = by_id.get(view.node_id)
        if node is None:
            continue
        if view.ip_blocked:
            result.notes[f"ip:{node.id}"] = (
                f"{node.name}: IP заблокирован в России (из Европы сервер работает) — "
                "нужен новый IP у хостинга"
            )
        elif view.dead:
            result.notes[f"dead:{node.id}"] = (
                f"{node.name}: недоступен ни из России, ни из Европы — сервер лежит "
                "или закрыт файрволом"
            )
        if getattr(node, "probe_hidden", False) and (view.any_ok or not auto_hide):
            result.unhide.append(node.id)
    # Сервер выключили руками или зонд выключили — скрытие снимаем.
    for node in nodes:
        if getattr(node, "probe_hidden", False) and node.id not in views and node.id not in result.unhide:
            result.unhide.append(node.id)

    if auto_hide and blocked:
        if len(blocked) * 2 > len(enabled):
            # Половина серверов «заблокирована» разом — скорее беда у самого
            # зонда (его сеть, его провайдер). Прятать всё нельзя.
            result.notes["hide:too-many"] = (
                f"из России недоступна большая часть серверов ({len(blocked)} из "
                f"{len(enabled)}) — серверы не скрываю: возможно, проблема у самого зонда"
            )
        else:
            visible = [
                node for node in enabled
                if not getattr(node, "probe_hidden", False) or node.id in result.unhide
            ]
            for view in blocked:
                node = by_id[view.node_id]
                if getattr(node, "probe_hidden", False):
                    continue
                if len([n for n in visible if n.id != node.id]) < 1:
                    break  # последний видимый сервер не прячем никогда
                result.hide.append(node.id)
                visible = [n for n in visible if n.id != node.id]

    # --- Порт режут: перенести подключение на другой порт --------------------
    if auto_port:
        inbound_nodes: Dict[int, List[int]] = {}
        inbounds: Dict[int, Any] = {}
        for node in enabled:
            for inbound in node.inbounds:
                inbound_nodes.setdefault(inbound.id, []).append(node.id)
                inbounds[inbound.id] = inbound
        for inbound_id, node_ids in inbound_nodes.items():
            inbound = inbounds[inbound_id]
            if inbound.protocol == ProxyType.hysteria2 or not inbound.is_enabled:
                continue
            if any(host.port for host in inbound.hosts if not host.is_disabled):
                continue  # у хостов свой порт — их порт панель не знает
            reachable: List[int] = []
            cut: List[int] = []
            for node_id in node_ids:
                view = views.get(node_id)
                if view is None or not view.any_ok:
                    continue
                reachable.append(node_id)
                own = [e for e in view.entries if e["inbound_id"] == inbound_id]
                if own and all(
                    _confirmed(e) and _tls(e) and not _tls(e).get("ok") and _control_ok(e)
                    for e in own
                ):
                    cut.append(node_id)
            if not cut or len(cut) * 2 < len(reachable):
                for node_id in cut:
                    result.notes[f"port:{inbound_id}:{node_id}"] = (
                        f"{by_id[node_id].name}: порт {inbound.port} ({inbound.tag}) режут из "
                        "России только на этом сервере — порт подключения общий, менять его "
                        "всем не стану. Поможет новый IP"
                    )
                continue
            last = (history.get("inbounds") or {}).get(str(inbound_id), {}).get("at")
            if last and now - datetime.fromisoformat(last) < PORT_COOLDOWN:
                result.notes[f"port-wait:{inbound_id}"] = (
                    f"{inbound.tag}: порт {inbound.port} снова режут, но его недавно уже "
                    "меняли — жду, чтобы не дёргать подписки"
                )
                continue
            result.move_ports.append((inbound_id, reachable))

    # --- Домен режут: сменить маскировку у сервера --------------------------
    if auto_domain:
        for view in views.values():
            node = by_id.get(view.node_id)
            if node is None or view.ip_blocked or view.dead or node.status != NodeStatus.connected:
                continue
            reality = [e for e in view.entries if e.get("security") == SecurityType.reality.value]
            for sni in sorted({e.get("sni") for e in reality if e.get("sni")}):
                same = [e for e in reality if e.get("sni") == sni]
                if any(e.get("state") == "ok" for e in same):
                    continue  # с этим доменом что-то работает — дело не в нём
                if not any(_confirmed(e) and _tls(e).get("ok") for e in same):
                    continue  # рукопожатие не проходит — это порт или IP
                state = (history.get("nodes") or {}).get(str(node.id), {})
                changes = [
                    datetime.fromisoformat(at) for at in state.get("domain_changes", [])
                    if now - datetime.fromisoformat(at) < timedelta(days=1)
                ]
                if changes and now - max(changes) < DOMAIN_COOLDOWN:
                    continue
                if len(changes) >= DOMAIN_DAILY_LIMIT:
                    result.notes[f"domain-limit:{node.id}"] = (
                        f"{node.name}: домен меняли {len(changes)} раза за сутки — не помогает. "
                        "Похоже, IP под замедлением: нужен новый IP"
                    )
                    continue
                result.rotate_domains.append((node.id, sni))
    return result


# --- Исполнение ---------------------------------------------------------------

def _log(history: Dict[str, Any], text: str, now: datetime) -> None:
    log = list(history.get("log") or [])
    log.insert(0, {"at": now.replace(microsecond=0).isoformat(), "text": text})
    history["log"] = log[:LOG_SIZE]


async def _panel_reach(host: str, port: int) -> str:
    from app.services.probe import reach

    answer = await reach(host, port)
    if answer.get("ok"):
        return "open"
    return "closed" if answer.get("error") == "порт закрыт" else "timeout"


async def _pick_port(client, inbound, nodes: Sequence[Any], from_russia_ids: Sequence[int]) -> Optional[int]:
    """Свободный порт, до которого и из России, и из Европы доходит TCP.

    На свободном порту никто не слушает, поэтому хороший ответ — «закрыт»
    (сервер отказал сразу), а «таймаут» — значит глушат по дороге или
    файрвол хостинга. «Открыт» из Европы — порт занят чем-то вне панели.
    """
    current = inbound.port
    for port in ports.CANDIDATES:
        if port == current:
            continue
        if ports.clashes(port, inbound.protocol, inbound.listen, nodes, exclude_id=inbound.id):
            continue
        hosts = [masking_address(node) for node in nodes]
        # Из России проверяем только серверы, до которых оттуда вообще
        # доходит: заблокированный IP не даст пройти ни одному порту.
        russian = [masking_address(node) for node in nodes if node.id in from_russia_ids]
        try:
            answer = await client.reach([{"host": host, "port": port} for host in russian])
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Зонд: проверка порта {port} не удалась: {exc}")
            return None
        from_russia = {item["host"]: item.get("state") for item in answer.get("results", [])}
        if any(from_russia.get(host) != "closed" for host in russian):
            continue
        from_europe = await asyncio.gather(*(_panel_reach(host, port) for host in hosts))
        if all(state == "closed" for state in from_europe):
            return port
    return None


def masking_address(node) -> str:
    return (node.address or "").split(",")[0].strip()


async def _public_ipv4(address: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(address, 443, family=socket.AF_INET)
    except OSError:
        return ""
    return infos[0][4][0] if infos else ""


def _taken_domains(nodes: Sequence[Any], except_node: int) -> Set[str]:
    taken: Set[str] = set()
    seen: Set[int] = set()
    for node in nodes:
        for inbound in node.inbounds:
            if inbound.security != SecurityType.reality or inbound.id in seen:
                continue
            seen.add(inbound.id)
            for other in nodes:
                if other.id == except_node or inbound not in other.inbounds:
                    continue
                domain = masking.domain_for(inbound.settings, other.id)
                if domain:
                    taken.add(domain)
    return taken


async def _pick_domain(client, node, nodes: Sequence[Any], avoid: Set[str]) -> Optional[str]:
    """Новый домен для сервера: годный от него самого (TLS 1.3, h2) и
    открывающийся из России. Сначала соседи по подсети, потом каталог."""
    from app.services.node_client import NodeClient, NodeError

    taken = _taken_domains(nodes, node.id) | avoid | set(masking.DISCOURAGED)
    candidates: List[str] = []
    agent = NodeClient(node)
    ip = await _public_ipv4(masking_address(node))
    if ip:
        try:
            found = await agent.neighbors(ip)
            for item in sorted(masking.usable_neighbors(found.get("results", [])),
                               key=lambda r: (r.get("ms") or 10**6, r["domain"])):
                candidates.append(item["domain"])
        except NodeError as exc:
            logger.info(f"Зонд: соседи {node.name} не найдены: {exc}")
    try:
        probed = await agent.probe_domains(list(masking.RECOMMENDED))
        for item in sorted((r for r in probed.get("results", []) if r.get("ok")),
                           key=lambda r: (r.get("ms") or 10**6, r["domain"])):
            candidates.append(item["domain"])
    except NodeError as exc:
        logger.info(f"Зонд: домены с {node.name} не проверены: {exc}")
    candidates = [d for d in dict.fromkeys(candidates) if d not in taken][:DOMAIN_CANDIDATES]
    if not candidates:
        return None
    try:
        answer = await client.probe_domains(candidates)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Зонд: домены из России не проверены: {exc}")
        return None
    opens = {item["domain"] for item in answer.get("results", []) if item.get("ok")}
    for domain in candidates:
        if domain in opens:
            return domain
    return None


def _set_node_domain(inbound, node_id: int, domain: str) -> None:
    settings = dict(inbound.settings or {})
    domains = dict(masking.node_domains(settings))
    domains[str(node_id)] = domain
    settings[masking.NODE_DOMAINS_KEY] = domains
    inbound.settings = settings  # новый словарь — иначе JSON-колонка не сохранится


async def apply(client, probe, nodes: Sequence[Any], todo: Plan, now: Optional[datetime] = None) -> Tuple[List[str], List[str]]:
    """Выполнить план. Возвращает (что сделано, о чём сообщить впервые)."""
    now = now or datetime.utcnow()
    history: Dict[str, Any] = {key: (dict(value) if isinstance(value, dict) else value)
                               for key, value in (probe.fixes or {}).items()}
    history.setdefault("inbounds", {})
    history.setdefault("nodes", {})
    done: List[str] = []
    by_id = {node.id: node for node in nodes}

    for node_id in todo.unhide:
        node = by_id[node_id]
        node.probe_hidden = False
        text = f"{node.name}: снова в подписке — из России работает"
        if not probe.auto_hide:
            text = f"{node.name}: снова в подписке — автоскрытие выключено"
        done.append(text)

    for node_id in todo.hide:
        node = by_id[node_id]
        node.probe_hidden = True
        done.append(f"{node.name}: убран из подписок, пока IP заблокирован в России — "
                    "вернётся сам, когда заработает")

    for inbound_id, russian_ids in todo.move_ports:
        inbound = next(i for n in nodes for i in n.inbounds if i.id == inbound_id)
        on = [node for node in nodes if node.is_enabled and inbound in node.inbounds]
        port = await _pick_port(client, inbound, on, russian_ids)
        if port is None:
            todo.notes[f"port-none:{inbound_id}"] = (
                f"{inbound.tag}: порт {inbound.port} режут из России, но свободного "
                "порта, который проходит, не нашлось — откройте порты 2053–2096 у хостинга"
            )
            continue
        old = inbound.port
        inbound.port = port
        history["inbounds"][str(inbound_id)] = {"at": now.isoformat(), "from": old, "to": port}
        todo.config_changed = True
        done.append(f"{inbound.tag}: порт {old} → {port} (порт {old} режут из России). "
                    "Ссылки у людей обновятся вместе с подпиской")

    for node_id, sni in todo.rotate_domains:
        node = by_id[node_id]
        state = dict(history["nodes"].get(str(node_id)) or {})
        bad = list(dict.fromkeys((state.get("bad_domains") or []) + [sni]))[-50:]
        domain = await _pick_domain(client, node, nodes, set(bad))
        state["bad_domains"] = bad
        if domain is None:
            todo.notes[f"domain-none:{node_id}"] = (
                f"{node.name}: домен {sni} режут, а замены, которая открывается из России, "
                "не нашлось — подберите домен на странице «Маскировка»"
            )
            history["nodes"][str(node_id)] = state
            continue
        changed = []
        for inbound in node.inbounds:
            if inbound.security == SecurityType.reality and masking.domain_for(inbound.settings, node.id) == sni:
                _set_node_domain(inbound, node.id, domain)
                changed.append(inbound.tag)
        state["domain_changes"] = [
            at for at in state.get("domain_changes", [])
            if now - datetime.fromisoformat(at) < timedelta(days=1)
        ] + [now.isoformat()]
        history["nodes"][str(node_id)] = state
        todo.config_changed = True
        done.append(f"{node.name}: маскировка {sni} → {domain} ({', '.join(changed)}) — "
                    "по старому домену соединение резали")

    # Сообщаем о неисправимом один раз, пока проблема не уйдёт.
    noted = dict(history.get("noted") or {})
    fresh = [text for key, text in todo.notes.items() if key not in noted]
    history["noted"] = {key: now.isoformat() for key in todo.notes} | {
        key: noted[key] for key in todo.notes if key in noted
    }
    for text in done:
        _log(history, text, now)
    probe.fixes = history
    return done, fresh


def report(probe_name: str, done: List[str], fresh: List[str]) -> str:
    lines: List[str] = []
    if done:
        lines.append(f"🛠 <b>Зонд «{probe_name}» исправил сам</b>")
        lines += [f"• {text}" for text in done]
    if fresh:
        if lines:
            lines.append("")
        lines.append("⚠️ <b>Сам не исправить</b>")
        lines += [f"• {text}" for text in fresh]
    return "\n".join(lines)
