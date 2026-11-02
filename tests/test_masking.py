"""Маскировочные домены: каталог, свой домен у сервера, раздача по проверке."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

from app.models.enums import NetworkType, ProxyType, SecurityType
from app.services import links, masking, presets, xray_config


def test_catalog_is_large_and_without_duplicates():
    assert len(masking.ALL_DOMAINS) >= 50
    assert len(masking.ALL_DOMAINS) == len(set(masking.ALL_DOMAINS))
    for domain in masking.ALL_DOMAINS:
        assert masking.is_valid(domain), domain


def test_guide_domains_are_not_recommended():
    """Домены из гайдов вычисляются первыми — по умолчанию их не выдаём."""
    for domain in ("www.microsoft.com", "dl.google.com", "www.cloudflare.com"):
        assert domain in masking.DISCOURAGED
        assert domain not in masking.RECOMMENDED
    # Тот, что у пользователя работает, — среди рекомендованных.
    assert "www.lovelive-anime.jp" in masking.RECOMMENDED


def test_input_is_cleaned_to_a_hostname():
    assert masking.clean(" https://WWW.Example.com/path ") == "www.example.com"
    assert masking.clean("www.example.com:443") == "www.example.com"
    assert masking.clean("www.example.com.") == "www.example.com"
    assert not masking.is_valid(masking.clean("not a domain"))
    assert not masking.is_valid("localhost")


def test_default_domain_is_not_the_same_for_everyone():
    """Фиксированное значение по умолчанию давало всем одну маску."""
    taken = masking.RECOMMENDED[:-1]
    assert masking.pick_default(taken) == masking.RECOMMENDED[-1]

    preset = presets.PRESETS_BY_KEY["vless_reality"]
    picked = {presets.build_settings(preset)["serverNames"][0] for _ in range(30)}
    assert len(picked) > 1
    assert not picked & masking.DISCOURAGED


def _reality_inbound(node_domains=None):
    settings = {
        "dest": "www.lovelive-anime.jp:443",
        "serverNames": ["www.lovelive-anime.jp"],
        "privateKey": "PRIV",
        "publicKey": "PUB",
        "shortIds": ["ab"],
        "fingerprint": "firefox",
    }
    if node_domains:
        settings[masking.NODE_DOMAINS_KEY] = node_domains
    return SimpleNamespace(
        id=1, tag="R", protocol=ProxyType.vless, listen="0.0.0.0", port=443,
        network=NetworkType.tcp, security=SecurityType.reality, settings=settings,
        sniffing=False, is_enabled=True, hosts=[],
    )


def _node(node_id):
    return SimpleNamespace(id=node_id, name=f"N{node_id}", address=f"n{node_id}.example.com",
                           country="FI", sort_order=0, hysteria_cert_sha256=None)


def test_node_gets_its_own_domain_in_xray_config():
    inbound = _reality_inbound({"2": "www.kone.com"})

    own = xray_config.build_inbound(inbound, [], node_id=2)["streamSettings"]["realitySettings"]
    shared = xray_config.build_inbound(inbound, [], node_id=1)["streamSettings"]["realitySettings"]

    assert own["dest"] == "www.kone.com:443"
    # Старое имя остаётся: подписки до смены домена должны подключаться.
    assert own["serverNames"] == ["www.kone.com", "www.lovelive-anime.jp"]
    assert shared["dest"] == "www.lovelive-anime.jp:443"
    assert shared["serverNames"] == ["www.lovelive-anime.jp"]


def test_link_uses_the_domain_of_its_server():
    inbound = _reality_inbound({"2": "www.kone.com"})
    user = SimpleNamespace(
        username="u", proxy_settings=lambda protocol: {"id": "11111111-2222-3333-4444-555555555555"},
    )

    assert "sni=www.kone.com" in links.build_link(user, inbound, _node(2))
    assert "sni=www.lovelive-anime.jp" in links.build_link(user, inbound, _node(1))


def test_duplicates_are_reported():
    inbound = _reality_inbound({"1": "www.kone.com", "2": "www.kone.com"})
    assert masking.duplicates(inbound.settings, [1, 2, 3]) == {"www.kone.com": [1, 2]}


def _probe(domain, ok=True, ms=50):
    return {"domain": domain, "ok": ok, "ms": ms if ok else None, "note": "годится" if ok else "таймаут"}


def test_summary_puts_widely_working_domains_first_and_guides_last():
    results = {
        1: [_probe("www.a.com", ms=90), _probe("www.b.com", ms=20), _probe("www.microsoft.com", ms=5)],
        2: [_probe("www.a.com", ms=80), _probe("www.b.com", ok=False), _probe("www.microsoft.com", ms=5)],
    }
    order = [row["domain"] for row in masking.summarize(results)]
    assert order == ["www.a.com", "www.b.com", "www.microsoft.com"]


def test_each_server_gets_a_distinct_working_domain():
    results = {
        # У первого сервера годится только один домен — его нельзя отдать соседу.
        1: [_probe("www.a.com", ms=90), _probe("www.b.com", ok=False)],
        2: [_probe("www.a.com", ms=10), _probe("www.b.com", ms=40)],
        3: [_probe("www.microsoft.com", ms=1)],
    }
    chosen = masking.assign_distinct([1, 2, 3], results)
    assert chosen == {1: "www.a.com", 2: "www.b.com"}


def _agent():
    spec = importlib.util.spec_from_file_location(
        "agent_under_test", Path(__file__).resolve().parent.parent / "agent" / "agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agent_probe_accepts_only_hostnames():
    """Ручка проверки не должна превращаться в сканер чего угодно."""
    agent = _agent()
    checked = []
    agent.probe_domain = lambda domain: checked.append(domain) or {"domain": domain, "ok": False}

    agent.probe({"domains": ["www.example.com", "127.0.0.1", "http://x", "a b", "WWW.EXAMPLE.COM"]})

    assert checked == ["www.example.com"]


def test_wildcard_covers_exactly_one_label():
    agent = _agent()
    assert agent._covers("www.example.com", ["*.example.com"])
    assert not agent._covers("a.b.example.com", ["*.example.com"])

    spec = importlib.util.spec_from_file_location("pick_dest", Path("scripts/pick_dest.py"))
    pick = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pick)
    assert not pick.covers("a.b.example.com", ["*.example.com"])
