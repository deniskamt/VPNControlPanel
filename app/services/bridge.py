"""Мост через Россию: пользователь → российский сервер → иностранный → интернет.

Зачем. На мобильном интернете в России всё чаще работают «белые списки»:
пропускаются только российские IP и российские сайты. Иностранный сервер
под ними недоступен, как его ни маскируй. Российский сервер доступен — и
дальше, уже из дата-центра, ведёт трафик за границу, где фильтров меньше
(это и проверяет зонд).

Как устроено. Мост — обычный сервер панели (Node с флагом bridge): у него
своё подключение с маскировкой под крупный российский сайт, пользователи,
учёт трафика — всё как у остальных. Отличие в выходе: вместо «прямо в
интернет» трафик уходит на иностранные серверы. Выходов несколько — по
одному на каждое подключение каждого иностранного сервера, — и Xray сам
раз в минуту проверяет их (observatory) и ведёт трафик через самый быстрый
живой (balancer leastPing). Сервер перестал отвечать — мост переключится
сам, без панели.

Ключ для выхода — служебный ключ зонда (probe_identity): иностранные
серверы его уже принимают. Трафик по нему на иностранных серверах не
считается, а людей считает сам мост.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from app.models.user import User

UPSTREAM_PREFIX = "up-"
BALANCER_TAG = "UPSTREAM"
PROBE_URL = "https://www.gstatic.com/generate_204"
PROBE_INTERVAL = "1m"
# Сколько выходов держать: на каждый Xray раз в минуту делает проверку.
MAX_UPSTREAMS = 24

# Маскировка моста — крупные российские сайты: под «белыми списками»
# пропускают именно их. Годный выбирается проверкой с самого моста
# (TLS 1.3 и HTTP/2 — требования REALITY).
RUSSIAN_DOMAINS = [
    "www.ozon.ru",
    "www.wildberries.ru",
    "www.avito.ru",
    "dzen.ru",
    "ya.ru",
    "vk.com",
    "ok.ru",
    "mail.ru",
    "www.kinopoisk.ru",
    "rutube.ru",
    "www.rbc.ru",
    "lenta.ru",
    "www.gosuslugi.ru",
    "www.sberbank.ru",
]

BRIDGE_TAG = "VLESS-REALITY-RU-BRIDGE"
BRIDGE_PORT = 443


def is_bridge(node: Any) -> bool:
    return bool(getattr(node, "bridge", False))


def upstream_nodes(nodes: Sequence[Any]) -> List[Any]:
    """Куда мост может вести трафик: включённые иностранные серверы, кроме
    убранных зондом (их IP заблокирован в России — оттуда не дойти)."""
    return [
        node for node in nodes
        if node.is_enabled and not is_bridge(node) and not getattr(node, "probe_hidden", False)
    ]


def upstream_outbounds(nodes: Sequence[Any], key: Optional[User]) -> List[Dict[str, Any]]:
    """Выходы моста — те же подключения, что получает пользователь, только
    со служебным ключом. Hysteria2 не годится: это не Xray."""
    if key is None:
        return []
    from app.services.probe import build_targets

    outbounds = []
    for target in build_targets(upstream_nodes(nodes), key)[:MAX_UPSTREAMS]:
        outbound = dict(target["outbound"])
        outbound["tag"] = UPSTREAM_PREFIX + target["key"].replace(":", "-")
        outbounds.append(outbound)
    return outbounds


def apply(config: Dict[str, Any], node: Any, upstreams: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Перестроить конфиг сервера в мост: трафик людей — в балансировщик."""
    user_tags = [
        inbound["tag"] for inbound in config.get("inbounds", [])
        if inbound.get("tag") and inbound.get("protocol") != "dokodemo-door"
    ]
    base = [o for o in config.get("outbounds", []) if o.get("tag") in ("DIRECT", "BLOCK")]
    rules = list(config.get("routing", {}).get("rules", []))
    if upstreams:
        # Первым — выход за границу: в Xray первый outbound — путь по
        # умолчанию, и «прямо из России» трафик уйти не должен.
        config["outbounds"] = upstreams + base
        config["observatory"] = {
            "subjectSelector": [UPSTREAM_PREFIX],
            "probeURL": PROBE_URL,
            "probeInterval": PROBE_INTERVAL,
            "enableConcurrency": True,
        }
        config.setdefault("routing", {})["balancers"] = [{
            "tag": BALANCER_TAG,
            "selector": [UPSTREAM_PREFIX],
            "strategy": {"type": "leastPing"},
        }]
        if user_tags:
            rules.append({"type": "field", "inboundTag": user_tags, "balancerTag": BALANCER_TAG})
    else:
        # Выходов нет — лучше честно не работать, чем тихо выпускать людей
        # в интернет из России под видом VPN.
        config["outbounds"] = [o for o in base if o.get("tag") == "BLOCK"] + [
            o for o in base if o.get("tag") != "BLOCK"
        ]
        if user_tags:
            rules.append({"type": "field", "inboundTag": user_tags, "outboundTag": "BLOCK"})
    config.setdefault("routing", {})["rules"] = rules
    return config


# --- Превращение сервера в мост -----------------------------------------------

async def pick_russian_domain(node: Any) -> str:
    """Маскировка моста: крупный российский сайт, который с этого сервера
    годится для REALITY (TLS 1.3 и HTTP/2), — самый быстрый."""
    from app.services.node_client import NodeClient, NodeError

    try:
        answer = await NodeClient(node).probe_domains(RUSSIAN_DOMAINS)
    except NodeError as exc:
        raise BridgeError(f"не удалось проверить домены с сервера: {exc}")
    good = sorted(
        (item for item in answer.get("results", []) if item.get("ok")),
        key=lambda item: (item.get("ms") or 10**6, item["domain"]),
    )
    if not good:
        raise BridgeError(
            "ни один российский сайт с этого сервера не подошёл для маскировки — "
            "проверьте, есть ли у сервера выход в интернет"
        )
    return good[0]["domain"]


class BridgeError(Exception):
    pass


async def make_bridge(session, node, domain: str) -> Dict[str, Any]:
    """Сделать сервер мостом: на нём остаётся одно подключение — мостовое,
    на 443 с российской маскировкой, — а трафик уходит за границу.

    Мостовое подключение одно на все мосты: у каждого моста свой домен
    (nodeDomains), ключи и порт общие. Создаётся при первом мосте и сразу
    выдаётся всем пользователям."""
    from sqlalchemy import select

    from app.models.inbound import Inbound
    from app.services import masking, presets, probe_identity
    from app.services import users as user_service

    if node.id is None:
        session.add(node)
        await session.flush()

    inbound = (await session.execute(
        select(Inbound).where(Inbound.tag == BRIDGE_TAG)
    )).scalars().first()
    created = inbound is None
    if created:
        template = presets.PRESETS_BY_KEY["vless_reality"]
        inbound = Inbound(
            tag=BRIDGE_TAG,
            remark="Мост через Россию",
            protocol=template.protocol,
            port=BRIDGE_PORT,
            network=template.network,
            security=template.security,
            listen="0.0.0.0",
            settings=presets.build_settings(template, masking_domain=domain),
        )
        session.add(inbound)

    dropped = [item.tag for item in node.inbounds if item is not inbound]
    node.inbounds = [inbound]
    node.bridge = True
    node.probe_hidden = False
    # Первым в списке: тем, у кого иностранные серверы не открываются, он и
    # нужен в первую очередь.
    node.sort_order = -1

    # Свой домен у каждого моста; новый словарь — иначе JSON не сохранится.
    settings = dict(inbound.settings or {})
    domains = dict(masking.node_domains(settings))
    domains[str(node.id)] = domain
    settings[masking.NODE_DOMAINS_KEY] = domains
    inbound.settings = settings
    await session.flush()
    granted = await user_service.grant_inbound_to_all(session, inbound) if created else 0
    # Выход моста — служебный ключ: иностранные серверы должны его принимать.
    await probe_identity.load(session, create=True)
    return {"inbound": inbound, "created": created, "granted": granted, "dropped": dropped}


async def unmake_bridge(session, node) -> List[str]:
    """Вернуть мост в обычный сервер: снова все включённые подключения
    (кроме мостового), трафик — прямо в интернет отсюда."""
    from sqlalchemy import select

    from app.models.inbound import Inbound
    from app.services import ports

    chosen = list((await session.execute(
        select(Inbound).where(Inbound.is_enabled.is_(True), Inbound.tag != BRIDGE_TAG)
    )).scalars().all())
    kept, _ = ports.split_clashing(chosen, node.agent_port)
    node.inbounds = kept
    node.bridge = False
    node.sort_order = 0
    return [item.tag for item in kept]
