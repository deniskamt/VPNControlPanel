"""Мост через Россию: конфиг моста ведёт трафик людей на иностранные серверы."""

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("SUBSCRIPTION_SECRET", "test-secret")

from app.models.enums import NetworkType, ProxyType, SecurityType, UserStatus  # noqa: E402
from app.services import bridge, probe_identity  # noqa: E402
from app.services.xray_config import build_node_config  # noqa: E402

XRAY = os.getenv("XRAY_TEST_BIN", "")
REALITY = {
    "dest": "www.microsoft.com:443", "serverNames": ["www.microsoft.com"],
    "privateKey": "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks",
    "publicKey": "E59WjnvZcQMu7tR7_BgyhycuRdBnnE7DPXdjCMXtXk8",
    "shortIds": ["ab12"], "flow": "xtls-rprx-vision",
}
KEY = {"vless": {"id": "99999999-9999-4999-8999-999999999999"},
       "vmess": {"id": "88888888-8888-4888-8888-888888888888"},
       "trojan": {"password": "p"}, "shadowsocks": {"password": "s"}}


def inbound(inbound_id, tag, port, **extra):
    data = dict(id=inbound_id, tag=tag, protocol=ProxyType.vless, listen="0.0.0.0", port=port,
                network=NetworkType.tcp, security=SecurityType.reality,
                settings=dict(REALITY), sniffing=True, is_enabled=True, hosts=[])
    data.update(extra)
    return SimpleNamespace(**data)


def node(node_id, inbounds, **extra):
    data = dict(id=node_id, name=f"N{node_id}", address=f"n{node_id}.example.com", country="DE",
                inbounds=inbounds, is_enabled=True, sort_order=node_id, bridge=False,
                probe_hidden=False)
    data.update(extra)
    return SimpleNamespace(**data)


def user(inbounds):
    return SimpleNamespace(
        username="user_1", status=UserStatus.active, expired=False, limited=False,
        inbounds=inbounds,
        proxy_settings=lambda wanted: {"id": "11111111-2222-3333-4444-555555555555"}
        if wanted == ProxyType.vless else None,
        allowed_on=lambda n: True,
    )


FOREIGN_IN = inbound(1, "VLESS-REALITY-VISION", 2053)
BRIDGE_IN = inbound(9, bridge.BRIDGE_TAG, 443,
                    settings=dict(REALITY, serverNames=["www.ozon.ru"], dest="www.ozon.ru:443"))


def setup():
    foreign = [node(1, [FOREIGN_IN]), node(2, [FOREIGN_IN]),
               node(3, [FOREIGN_IN], probe_hidden=True), node(4, [FOREIGN_IN], is_enabled=False)]
    ru = node(9, [BRIDGE_IN], bridge=True, country="RU", address="153.0.0.1")
    return foreign, ru


def test_upstreams_skip_bridge_hidden_and_disabled_servers():
    foreign, ru = setup()
    outbounds = bridge.upstream_outbounds(foreign + [ru], probe_identity.as_user(KEY))
    assert [o["tag"] for o in outbounds] == ["up-1-1-0", "up-2-1-0"]
    server = outbounds[0]["settings"]["vnext"][0]
    assert server["address"] == "n1.example.com" and server["port"] == 2053
    assert server["users"][0]["id"] == KEY["vless"]["id"]
    assert bridge.upstream_outbounds(foreign, None) == []


def bridge_config(upstreams):
    foreign, ru = setup()
    return build_node_config(ru, [user([BRIDGE_IN])], probe_identity.as_user(KEY), upstreams)


def test_bridge_routes_people_to_balancer_never_direct():
    foreign, _ = setup()
    upstreams = bridge.upstream_outbounds(foreign, probe_identity.as_user(KEY))
    config = bridge_config(upstreams)
    # Путь по умолчанию — за границу, а не «прямо из России».
    assert config["outbounds"][0]["tag"].startswith(bridge.UPSTREAM_PREFIX)
    assert config["routing"]["balancers"][0]["strategy"]["type"] == "leastPing"
    rule = config["routing"]["rules"][-1]
    assert rule == {"type": "field", "inboundTag": [bridge.BRIDGE_TAG],
                    "balancerTag": bridge.BALANCER_TAG}
    assert config["observatory"]["subjectSelector"] == [bridge.UPSTREAM_PREFIX]
    # Обычный сервер мостом не становится.
    plain = build_node_config(foreign[0], [user([FOREIGN_IN])])
    assert "balancers" not in plain["routing"] and plain["outbounds"][0]["tag"] == "DIRECT"


def test_bridge_without_upstreams_blocks_instead_of_leaking():
    config = bridge_config([])
    assert config["outbounds"][0]["tag"] == "BLOCK"
    assert config["routing"]["rules"][-1]["outboundTag"] == "BLOCK"


@pytest.mark.skipif(not (XRAY and Path(XRAY).exists()), reason="нужен настоящий Xray в XRAY_TEST_BIN")
def test_real_xray_accepts_bridge_config(tmp_path):
    foreign, _ = setup()
    config = bridge_config(bridge.upstream_outbounds(foreign, probe_identity.as_user(KEY)))
    # Служебные пути агента на тестовой машине не нужны.
    config["log"] = {"loglevel": "warning"}
    config["inbounds"][0]["port"] = 0
    # geoip.dat на тестовой машине нет — правило про частные адреса убираем.
    config["routing"]["rules"] = [r for r in config["routing"]["rules"] if "ip" not in r]
    path = tmp_path / "bridge.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    result = subprocess.run([XRAY, "run", "-test", "-config", str(path)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
