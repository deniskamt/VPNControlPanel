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
