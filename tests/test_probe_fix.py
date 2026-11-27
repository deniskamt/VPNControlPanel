"""Самолечение зонда: что он решает исправлять по результатам проверки.

Сценарий взят из живой проверки: порт 443 (XHTTP) режут из России на всех
серверах, 2053 (VISION) проходит; у двух серверов IP заблокирован целиком.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace

from app.models.enums import NodeStatus, ProxyType, SecurityType
from app.services import probe_fix

NOW = datetime(2026, 11, 25, 15, 0)


def inbound(inbound_id, tag, port):
    return SimpleNamespace(id=inbound_id, tag=tag, port=port, protocol=ProxyType.vless,
                           listen="0.0.0.0", is_enabled=True, hosts=[],
                           security=SecurityType.reality, settings={})


VISION = inbound(1, "VLESS-REALITY-VISION", 2053)
XHTTP = inbound(2, "VLESS-REALITY-XHTTP", 443)


def node(node_id, hidden=False, status=NodeStatus.connected):
    return SimpleNamespace(id=node_id, name=f"N{node_id}", is_enabled=True, probe_hidden=hidden,
                           status=status, inbounds=[VISION, XHTTP], agent_port=8443,
                           address=f"10.0.0.{node_id}")


def ok(sni="d.example"):
    return {"state": "ok", "fail_streak": 0, "ok_streak": 5, "security": "reality", "sni": sni,
            "tls": {"ok": True}, "tunnel": {"ok": True}, "download": {"ok": True}}


def port_cut(sni="d.example", streak=2):
    """До порта не доходит даже TCP, из Европы — доходит."""
    return {"state": "fail", "fail_streak": streak, "security": "reality", "sni": sni,
            "tls": {"ok": False, "error": "таймаут"}, "tunnel": {"ok": False},
            "control": {"ok": True}}


def sni_cut(sni="d.example", streak=2):
    """Рукопожатие есть, данные режут."""
    return {"state": "fail", "fail_streak": streak, "security": "reality", "sni": sni,
            "tls": {"ok": True}, "tunnel": {"ok": False, "error": "таймаут"}}


def results(per_node):
    merged = {}
    for node_id, (vision, xhttp) in per_node.items():
        merged[f"{node_id}:1:0"] = dict(vision, node=f"N{node_id}")
        merged[f"{node_id}:2:0"] = dict(xhttp, node=f"N{node_id}")
    return merged


def test_live_case_moves_port_and_hides_blocked_servers():
    nodes = [node(i) for i in range(1, 8)]
    merged = results({
        1: (ok(), port_cut()), 2: (ok(), port_cut()), 3: (ok(), port_cut()),
        4: (ok(), port_cut()), 5: (ok(), port_cut()),
        6: (port_cut(), port_cut()),   # IP заблокирован
        7: (port_cut(), port_cut()),   # IP заблокирован
    })
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.move_ports == [(2, [1, 2, 3, 4, 5])]
    assert sorted(todo.hide) == [6, 7]
    assert todo.rotate_domains == []
    assert "ip:6" in todo.notes and "нужен новый IP" in todo.notes["ip:6"]


def test_single_unconfirmed_failure_changes_nothing():
    nodes = [node(1), node(2)]
    merged = results({1: (ok(), port_cut(streak=1)), 2: (port_cut(streak=1), port_cut(streak=1))})
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.empty


def test_port_cut_on_one_server_only_is_not_moved_for_everyone():
    nodes = [node(i) for i in range(1, 5)]
    merged = results({1: (ok(), port_cut()), 2: (ok(), ok()), 3: (ok(), ok()), 4: (ok(), ok())})
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.move_ports == []
    assert "port:2:1" in todo.notes


def test_port_cooldown():
    nodes = [node(1), node(2)]
    merged = results({1: (ok(), port_cut()), 2: (ok(), port_cut())})
    history = {"inbounds": {"2": {"at": (NOW - timedelta(hours=1)).isoformat()}}}
    assert probe_fix.plan(nodes, merged, history, now=NOW).move_ports == []
    history = {"inbounds": {"2": {"at": (NOW - timedelta(hours=7)).isoformat()}}}
    assert probe_fix.plan(nodes, merged, history, now=NOW).move_ports == [(2, [1, 2])]


def test_handshake_ok_but_data_cut_rotates_domain():
    nodes = [node(1), node(2)]
    merged = results({1: (sni_cut("bad.example"), sni_cut("bad.example")), 2: (ok(), ok())})
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.rotate_domains == [(1, "bad.example")]
    assert todo.hide == []


def test_domain_kept_when_it_works_on_another_connection():
    nodes = [node(1)]
    merged = results({1: (ok("same.example"), sni_cut("same.example"))})
    assert probe_fix.plan(nodes, merged, {}, now=NOW).rotate_domains == []


def test_domain_rotation_limits():
    nodes = [node(1)]
    merged = results({1: (sni_cut(), sni_cut())})
    recent = {"nodes": {"1": {"domain_changes": [(NOW - timedelta(minutes=5)).isoformat()]}}}
    assert probe_fix.plan(nodes, merged, recent, now=NOW).rotate_domains == []

    three = {"nodes": {"1": {"domain_changes": [
        (NOW - timedelta(hours=h)).isoformat() for h in (1, 2, 3)]}}}
    todo = probe_fix.plan(nodes, merged, three, now=NOW)
    assert todo.rotate_domains == [] and "domain-limit:1" in todo.notes


def test_disconnected_server_is_not_touched():
    # Сервер не принял конфиг — ключа проверки на нём может не быть.
    nodes = [node(1, status=NodeStatus.error)]
    merged = results({1: (sni_cut(), sni_cut())})
    assert probe_fix.plan(nodes, merged, {}, now=NOW).rotate_domains == []


def test_too_many_blocked_means_probe_problem():
    nodes = [node(i) for i in range(1, 4)]
    merged = results({1: (port_cut(), port_cut()), 2: (port_cut(), port_cut()), 3: (ok(), ok())})
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.hide == [] and "hide:too-many" in todo.notes


def test_last_visible_server_is_never_hidden():
    nodes = [node(1), node(2, hidden=True), node(3, hidden=True), node(4)]
    merged = results({1: (port_cut(), port_cut()), 2: (port_cut(), port_cut()),
                      3: (ok(), ok()), 4: (ok(), ok())})
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    # №3 снова работает и возвращается — тогда №1 прятать можно.
    assert todo.unhide == [3] and todo.hide == [1]

    nodes = [node(1), node(2, hidden=True)]
    merged = results({1: (port_cut(), port_cut()), 2: (port_cut(), port_cut())})
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.hide == []


def test_hidden_server_returns_when_it_works_or_autohide_is_off():
    nodes = [node(1, hidden=True), node(2)]
    still_blocked = results({1: (port_cut(), port_cut()), 2: (ok(), ok())})
    assert probe_fix.plan(nodes, still_blocked, {}, now=NOW).unhide == []
    assert probe_fix.plan(nodes, still_blocked, {}, auto_hide=False, now=NOW).unhide == [1]
    works = results({1: (ok(), port_cut()), 2: (ok(), ok())})
    assert probe_fix.plan(nodes, works, {}, now=NOW).unhide == [1]


def test_switches_turn_fixes_off():
    nodes = [node(i) for i in range(1, 8)]
    merged = results({**{i: (ok(), port_cut()) for i in range(1, 6)},
                      6: (port_cut(), port_cut()), 7: (sni_cut(), sni_cut())})
    todo = probe_fix.plan(nodes, merged, {}, auto_hide=False, auto_port=False,
                          auto_domain=False, now=NOW)
    assert todo.empty


class FakeProbeAgent:
    """Зонд: 2083 из России проходит (сервер отвечает отказом), 2087 глушат."""

    def __init__(self):
        self.asked = []

    async def reach(self, targets):
        self.asked.append(targets)
        return {"results": [
            {"host": t["host"], "port": t["port"],
             "state": "closed" if t["port"] == 2083 else "timeout"} for t in targets
        ]}


def test_apply_moves_port_to_one_that_passes(monkeypatch):
    import asyncio

    async def panel_reach(host, port):
        return "closed"

    monkeypatch.setattr(probe_fix, "_panel_reach", panel_reach)
    xhttp = inbound(2, "VLESS-REALITY-XHTTP", 443)
    vision = inbound(1, "VLESS-REALITY-VISION", 2053)
    nodes = []
    for i in (1, 2, 3):
        n = node(i)
        n.inbounds = [vision, xhttp]
        nodes.append(n)
    agent = FakeProbeAgent()
    probe = SimpleNamespace(fixes={}, auto_hide=True)
    todo = probe_fix.Plan(move_ports=[(2, [1, 2])], hide=[3])
    done, _ = asyncio.run(probe_fix.apply(agent, probe, nodes, todo, now=NOW))

    assert xhttp.port == 2083            # 2053 занят VISION, 2083 проходит
    assert nodes[2].probe_hidden is True
    assert todo.config_changed
    # Заблокированный №3 в проверку порта из России не попадает.
    assert {t["host"] for t in agent.asked[-1]} == {"10.0.0.1", "10.0.0.2"}
    assert probe.fixes["inbounds"]["2"]["from"] == 443
    assert any("443 → 2083" in line for line in done)
    assert probe.fixes["log"][0]["text"] in done
    assert "исправил сам" in probe_fix.report("Россия", done, [])


def test_apply_rotates_domain_only_where_it_was_used(monkeypatch):
    import asyncio

    picked = {}

    async def pick(client, node_obj, nodes, avoid):
        picked["avoid"] = avoid
        return "fresh.example"

    monkeypatch.setattr(probe_fix, "_pick_domain", pick)
    shared = {"serverNames": ["common.example"], "nodeDomains": {"1": "bad.example"}}
    vision = inbound(1, "VLESS-REALITY-VISION", 2053)
    vision.settings = dict(shared)
    xhttp = inbound(2, "VLESS-REALITY-XHTTP", 443)
    xhttp.settings = {"serverNames": ["other.example"]}
    first, second = node(1), node(2)
    first.inbounds = second.inbounds = [vision, xhttp]
    probe = SimpleNamespace(fixes={}, auto_hide=True)
    todo = probe_fix.Plan(rotate_domains=[(1, "bad.example")])
    done, _ = asyncio.run(probe_fix.apply(object(), probe, [first, second], todo, now=NOW))

    assert vision.settings["nodeDomains"] == {"1": "fresh.example"}
    assert "nodeDomains" not in xhttp.settings          # там был другой домен
    assert "bad.example" in picked["avoid"]             # плохой домен не вернётся
    assert probe.fixes["nodes"]["1"]["bad_domains"] == ["bad.example"]
    assert any("bad.example → fresh.example" in line for line in done)


def test_unfixable_is_reported_once():
    import asyncio

    probe = SimpleNamespace(fixes={}, auto_hide=True)
    todo = probe_fix.Plan(notes={"ip:6": "N6: IP заблокирован"})
    _, fresh = asyncio.run(probe_fix.apply(object(), probe, [], todo, now=NOW))
    assert fresh == ["N6: IP заблокирован"]
    todo = probe_fix.Plan(notes={"ip:6": "N6: IP заблокирован"})
    _, fresh = asyncio.run(probe_fix.apply(object(), probe, [], todo, now=NOW))
    assert fresh == []
    # Проблема ушла и вернулась — снова сообщаем.
    asyncio.run(probe_fix.apply(object(), probe, [], probe_fix.Plan(), now=NOW))
    _, fresh = asyncio.run(probe_fix.apply(object(), probe, [], probe_fix.Plan(notes={"ip:6": "x"}), now=NOW))
    assert fresh == ["x"]


def test_hosts_with_own_port_are_reported_not_skipped_silently():
    xhttp = inbound(2, "VLESS-REALITY-XHTTP", 443)
    xhttp.hosts = [SimpleNamespace(port=443, is_disabled=False)]
    nodes = [node(1), node(2)]
    for n in nodes:
        n.inbounds = [VISION, xhttp]
    merged = results({1: (ok(), port_cut()), 2: (ok(), port_cut())})
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.move_ports == [] and "port-hosts:2" in todo.notes


def test_open_problems_are_kept_for_the_page():
    import asyncio

    probe = SimpleNamespace(fixes={}, auto_hide=True)
    asyncio.run(probe_fix.apply(object(), probe, [], probe_fix.Plan(notes={"a": "текст"}), now=NOW))
    assert probe.fixes["open"] == ["текст"]


def test_blocked_server_firewall_does_not_veto_new_port(monkeypatch):
    """Живой случай: заблокированный сервер глушит все порты (файрвол
    хостинга) — это не повод оставлять остальным порт, который режут."""
    import asyncio

    async def panel_reach(host, port):
        if host == "10.0.0.3":
            return "timeout"
        if host == "10.0.0.1" and port == 2083:
            return "open"      # 2083 на первом сервере занят чем-то чужим
        return "closed"

    monkeypatch.setattr(probe_fix, "_panel_reach", panel_reach)

    class Agent:
        async def reach(self, targets):
            return {"results": [{"host": t["host"], "port": t["port"], "state": "closed"}
                                for t in targets]}

    xhttp = inbound(2, "VLESS-REALITY-XHTTP", 443)
    vision = inbound(1, "VLESS-REALITY-VISION", 2053)
    nodes = [node(1), node(2), node(3)]
    for n in nodes:
        n.inbounds = [vision, xhttp]
    probe = SimpleNamespace(fixes={}, auto_hide=True)
    todo = probe_fix.Plan(move_ports=[(2, [1, 2])])
    asyncio.run(probe_fix.apply(Agent(), probe, nodes, todo, now=NOW))
    assert xhttp.port == 2087   # 2083 занят на №1, «таймаут» у №3 не мешает

    # У работающего сервера таймаут из Европы — порт не годится.
    async def strict(host, port):
        return "timeout" if host == "10.0.0.2" else "closed"

    monkeypatch.setattr(probe_fix, "_panel_reach", strict)
    xhttp.port = 443
    todo = probe_fix.Plan(move_ports=[(2, [1, 2])])
    asyncio.run(probe_fix.apply(Agent(), probe, nodes, todo, now=NOW))
    assert xhttp.port == 443 and "port-none:2" in todo.notes



def test_blinking_server_is_not_returned_on_first_success():
    """Живой случай: Berlin #2 то доступен, то нет — убирали и возвращали
    каждый час. Возвращаем только после нескольких удачных проверок подряд."""
    nodes = [node(1, hidden=True), node(2)]
    one_ok = dict(ok(), ok_streak=1)
    merged = results({1: (one_ok, port_cut()), 2: (ok(), ok())})
    assert probe_fix.plan(nodes, merged, {}, now=NOW).unhide == []

    three = dict(ok(), ok_streak=3)
    merged = results({1: (three, port_cut()), 2: (ok(), ok())})
    assert probe_fix.plan(nodes, merged, {}, now=NOW).unhide == [1]

    # Уже дважды убирали за сутки — нужно два часа стабильной работы.
    flapping = {"nodes": {"1": {"hidden_at": [
        (NOW - timedelta(hours=h)).isoformat() for h in (2, 6)]}}}
    todo = probe_fix.plan(nodes, merged, flapping, now=NOW)
    assert todo.unhide == [] and "flap:1" in todo.notes
    long_ok = dict(ok(), ok_streak=8)
    merged = results({1: (long_ok, port_cut()), 2: (ok(), ok())})
    assert probe_fix.plan(nodes, merged, flapping, now=NOW).unhide == [1]
    # Старые скрытия (больше суток назад) не считаются.
    old = {"nodes": {"1": {"hidden_at": [(NOW - timedelta(days=2)).isoformat()] * 3}}}
    merged = results({1: (three, port_cut()), 2: (ok(), ok())})
    assert probe_fix.plan(nodes, merged, old, now=NOW).unhide == [1]


def test_hide_is_remembered_for_flap_detection():
    import asyncio

    nodes = [node(1), node(2)]
    probe = SimpleNamespace(fixes={}, auto_hide=True)
    asyncio.run(probe_fix.apply(object(), probe, nodes, probe_fix.Plan(hide=[1]), now=NOW))
    assert probe.fixes["nodes"]["1"]["hidden_at"] == [NOW.isoformat()]
    assert probe_fix.recent_hides(probe.fixes, 1, NOW) == 1


def test_ok_streak_counts_consecutive_successes():
    from app.services import probe as probe_service

    target = {"key": "1:1:0", "label": {"node": "N1"}}
    good = {"key": "1:1:0", "tunnel": {"ok": True}, "download": {"ok": True}}
    bad = {"key": "1:1:0", "tunnel": {"ok": False}}
    state, _ = probe_service.merge({}, [target], [good], "t1")
    state, _ = probe_service.merge(state, [target], [good], "t2")
    assert state["1:1:0"]["ok_streak"] == 2
    state, _ = probe_service.merge(state, [target], [bad], "t3")
    assert state["1:1:0"]["ok_streak"] == 0



def test_server_where_nothing_works_is_hidden_even_if_handshake_passes():
    """Живой случай: Berlin #2 — на XHTTP рукопожатие есть, данные режут, на
    VISION не доходит вовсе. Людям сервер бесполезен — убираем."""
    nodes = [node(i) for i in range(1, 5)]
    merged = results({1: (port_cut(), sni_cut()), 2: (ok(), ok()), 3: (ok(), ok()),
                      4: (ok(), ok())})
    # Сначала — смена домена, из подписок пока не убираем.
    todo = probe_fix.plan(nodes, merged, {}, now=NOW)
    assert todo.rotate_domains == [(1, "d.example")] and todo.hide == []
    # Домен уже меняли трижды за сутки (как у Berlin #2) — убираем.
    tried = {"nodes": {"1": {"domain_changes": [
        (NOW - timedelta(hours=h)).isoformat() for h in (1, 2, 3)]}}}
    todo = probe_fix.plan(nodes, merged, tried, now=NOW)
    assert todo.hide == [1] and "cut:1" in todo.notes

    # Хоть одно подключение работает — сервер остаётся.
    merged = results({1: (ok(), sni_cut()), 2: (ok(), ok()), 3: (ok(), ok()), 4: (ok(), ok())})
    assert probe_fix.plan(nodes, merged, tried, now=NOW).hide == []

    # Сервер не принял конфиг — провал может быть из-за ключа, не прячем.
    nodes[0].status = NodeStatus.error
    merged = results({1: (port_cut(), sni_cut()), 2: (ok(), ok()), 3: (ok(), ok()),
                      4: (ok(), ok())})
    assert probe_fix.plan(nodes, merged, tried, now=NOW).hide == []


def _rotation_setup(monkeypatch, candidates):
    async def pick(client, node_obj, nodes, avoid):
        return [d for d in candidates if d not in avoid]

    monkeypatch.setattr(probe_fix, "_pick_domains", pick)
    vision = inbound(1, "VLESS-REALITY-VISION", 2053)
    vision.settings = {"serverNames": ["x"], "nodeDomains": {"1": "bad.example"}}
    xhttp = inbound(2, "VLESS-REALITY-XHTTP", 10443)
    xhttp.settings = {"serverNames": ["x"], "nodeDomains": {"1": "bad.example"}}
    n = node(1)
    n.inbounds = [vision, xhttp]
    return n, vision, xhttp


def test_search_keeps_trying_until_tunnel_works(monkeypatch):
    import asyncio

    n, vision, xhttp = _rotation_setup(monkeypatch, ["c1.example", "c2.example", "c3.example", "c4.example"])
    seen = []

    async def works(node_obj):
        domain = probe_fix.masking.domain_for(vision.settings, node_obj.id)
        seen.append(domain)
        return domain == "c3.example"

    probe = SimpleNamespace(fixes={}, auto_hide=True)
    todo = probe_fix.Plan(rotate_domains=[(1, "bad.example")])
    done, _ = asyncio.run(probe_fix.apply(object(), probe, [n], todo, now=NOW, try_domain=works))
    assert seen == ["c1.example", "c2.example", "c3.example"]       # дальше не пошёл
    assert probe_fix.masking.domain_for(vision.settings, 1) == "c3.example"
    assert probe_fix.masking.domain_for(xhttp.settings, 1) == "c3.example"
    assert "подобран рабочий домен c3.example" in done[0] and "попыток: 3" in done[0]
    bad = probe.fixes["nodes"]["1"]["bad_domains"]
    assert {"bad.example", "c1.example", "c2.example"} <= set(bad) and "c3.example" not in bad


def test_search_gives_up_and_restores_old_domain(monkeypatch):
    import asyncio

    n, vision, _ = _rotation_setup(monkeypatch, ["c1.example", "c2.example"])
    calls = []

    async def never(node_obj):
        calls.append(probe_fix.masking.domain_for(vision.settings, node_obj.id))
        return False

    probe = SimpleNamespace(fixes={}, auto_hide=True)
    todo = probe_fix.Plan(rotate_domains=[(1, "bad.example")])
    done, fresh = asyncio.run(probe_fix.apply(object(), probe, [n], todo, now=NOW, try_domain=never))
    assert done == [] and not todo.config_changed
    # Перепробовал оба и вернул прежний (последний вызов — заливка прежнего конфига).
    assert calls == ["c1.example", "c2.example", "bad.example"]
    assert probe_fix.masking.domain_for(vision.settings, 1) == "bad.example"
    assert any("нужен новый IP" in text for text in fresh)
