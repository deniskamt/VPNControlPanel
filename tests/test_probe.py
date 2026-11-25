"""Зонд: что он проверяет, как сводит результаты и что попадает на серверы."""

import os
from types import SimpleNamespace

os.environ.setdefault("SUBSCRIPTION_SECRET", "test-secret")

from app.models.enums import NetworkType, ProxyType, SecurityType, UserStatus  # noqa: E402
from app.services import probe, probe_identity, stats_email  # noqa: E402
from app.services.xray_config import build_node_config  # noqa: E402

REALITY = {
    "dest": "www.microsoft.com:443",
    "serverNames": ["www.microsoft.com"],
    "privateKey": "PRIVATE",
    "publicKey": "PUBLIC",
    "shortIds": ["ab12"],
    "flow": "xtls-rprx-vision",
}

PROBE_KEY = {
    "vless": {"id": "99999999-9999-4999-8999-999999999999"},
    "vmess": {"id": "88888888-8888-4888-8888-888888888888"},
    "trojan": {"password": "probe-pass"},
    "shadowsocks": {"password": "probe-ss"},
}


def make_inbound(**overrides):
    data = {
        "id": 1, "tag": "VLESS-REALITY", "protocol": ProxyType.vless,
        "listen": "0.0.0.0", "port": 443, "network": NetworkType.tcp,
        "security": SecurityType.reality, "settings": dict(REALITY),
        "sniffing": True, "is_enabled": True, "hosts": [],
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def make_node(inbounds, **overrides):
    data = {
        "id": 1, "name": "DE-1", "address": "de1.example.com", "country": "DE",
        "inbounds": inbounds, "is_enabled": True, "sort_order": 0,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def key():
    return probe_identity.as_user(PROBE_KEY)


def test_targets_use_each_servers_own_masking_domain():
    settings = dict(REALITY, nodeDomains={"2": "www.nvidia.com"})
    inbound = make_inbound(settings=settings)
    first = make_node([inbound])
    second = make_node([inbound], id=2, name="NL-1", address="nl1.example.com", sort_order=1)

    targets = probe.build_targets([second, first], key())
    assert [t["key"] for t in targets] == ["1:1:0", "2:1:0"]
    by_node = {t["label"]["node"]: t for t in targets}

    # Общий домен у первого, свой — у второго, как в подписке.
    assert by_node["DE-1"]["sni"] == "www.microsoft.com"
    assert by_node["NL-1"]["sni"] == "www.nvidia.com"
    reality = by_node["NL-1"]["outbound"]["streamSettings"]["realitySettings"]
    assert reality["serverName"] == "www.nvidia.com"
    # Подключаемся к адресу именно этого сервера и с ключом зонда.
    server = by_node["NL-1"]["outbound"]["settings"]["vnext"][0]
    assert server["address"] == "nl1.example.com"
    assert server["users"][0]["id"] == PROBE_KEY["vless"]["id"]
    assert by_node["NL-1"]["host"] == "nl1.example.com" and by_node["NL-1"]["port"] == 443


def test_disabled_servers_inbounds_and_hysteria_are_skipped():
    hysteria = make_inbound(id=2, tag="HY2", protocol=ProxyType.hysteria2,
                            network=NetworkType.tcp, security=SecurityType.tls, settings={})
    off = make_inbound(id=3, tag="OFF", is_enabled=False)
    nodes = [
        make_node([make_inbound(), hysteria, off]),
        make_node([make_inbound()], id=2, is_enabled=False),
    ]
    assert [t["key"] for t in probe.build_targets(nodes, key())] == ["1:1:0"]


def _result(key, tunnel=True, download=True):
    return {"key": key, "tls": {"ok": True, "ms": 40},
            "tunnel": {"ok": tunnel, "error": None if tunnel else "таймаут"},
            "download": {"ok": download, "bytes": 1_000_000 if download else 12_000,
                         "error": None if download else "соединение замерзает"}}


def test_merge_alerts_after_two_failures_and_on_recovery():
    targets = probe.build_targets([make_node([make_inbound()])], key())
    state, events = probe.merge({}, targets, [_result("1:1:0")], "t1")
    assert state["1:1:0"]["state"] == "ok" and events == []

    # Один провал — ещё не повод будить админа.
    state, events = probe.merge(state, targets, [_result("1:1:0", tunnel=False)], "t2")
    assert state["1:1:0"]["fail_streak"] == 1 and events == []
    assert state["1:1:0"]["last_ok_at"] == "t1"

    state, events = probe.merge(state, targets, [_result("1:1:0", tunnel=False)], "t3")
    assert [kind for kind, _ in events] == ["down"]
    assert "Из «Россия» не работает" in probe.alert_text("Россия", events)

    # Повторно о том же не пишем.
    state, events = probe.merge(state, targets, [_result("1:1:0", tunnel=False)], "t4")
    assert events == []

    state, events = probe.merge(state, targets, [_result("1:1:0")], "t5")
    assert [kind for kind, _ in events] == ["up"]
    assert state["1:1:0"]["fail_streak"] == 0 and state["1:1:0"]["alerted"] is False


def test_frozen_download_is_slow_not_ok():
    targets = probe.build_targets([make_node([make_inbound()])], key())
    state, _ = probe.merge({}, targets, [_result("1:1:0", download=False)], "t1")
    entry = state["1:1:0"]
    assert entry["state"] == "slow"
    assert "загрузка обрывается" in entry["reason"]


def test_missing_result_counts_as_failure():
    targets = probe.build_targets([make_node([make_inbound()])], key())
    state, _ = probe.merge({}, targets, [], "t1")
    assert state["1:1:0"]["state"] == "fail"


def test_probe_key_goes_to_server_config_only_when_given():
    inbound = make_inbound()
    user = SimpleNamespace(
        username="user_1", status=UserStatus.active, expired=False, limited=False,
        inbounds=[inbound],
        proxy_settings=lambda wanted: {"id": "11111111-2222-3333-4444-555555555555"}
        if wanted == ProxyType.vless else None,
        allowed_on=lambda node: True,
    )
    node = make_node([inbound])

    def names(config):
        return [stats_email.parse(c["email"])[0] for c in config["inbounds"][1]["settings"]["clients"]]

    assert names(build_node_config(node, [user])) == ["user_1"]
    assert sorted(names(build_node_config(node, [user], key()))) == ["__probe__", "user_1"]
