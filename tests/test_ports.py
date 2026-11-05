"""Порты подключений: Xray общий порт не отвергает, а делит вслепую.

Проверено на Xray 25.10: одно подключение на порту — 40 соединений из 40,
два на одном порту — 20 из 40. Ошибки при этом нет нигде.
"""

from types import SimpleNamespace

from app.models.enums import ProxyType
from app.services import ports


def inbound(id, port, protocol=ProxyType.vless, listen="0.0.0.0", enabled=True, tag=None):
    return SimpleNamespace(id=id, port=port, protocol=protocol, listen=listen,
                           is_enabled=enabled, tag=tag or f"I{id}")


def node(inbounds, agent_port=8443, name="N"):
    return SimpleNamespace(name=name, agent_port=agent_port, inbounds=inbounds)


def test_two_tcp_inbounds_on_one_port_clash():
    server = node([inbound(1, 443), inbound(2, 443)])
    assert [(a.id, b.id) for a, b in ports.node_conflicts(server)] == [(1, 2)]


def test_udp_and_tcp_share_a_number_without_trouble():
    server = node([inbound(1, 443), inbound(2, 443, ProxyType.hysteria2)])
    assert ports.node_conflicts(server) == []


def test_different_addresses_do_not_clash_but_any_address_does():
    assert ports.node_conflicts(node([inbound(1, 443, listen="10.0.0.1"),
                                      inbound(2, 443, listen="10.0.0.2")])) == []
    assert ports.node_conflicts(node([inbound(1, 443, listen="10.0.0.1"),
                                      inbound(2, 443)])) != []


def test_disabled_inbound_does_not_hold_the_port():
    assert ports.node_conflicts(node([inbound(1, 443), inbound(2, 443, enabled=False)])) == []


def test_agent_port_is_taken():
    found = ports.clashes(8443, ProxyType.vless, "0.0.0.0", [node([])])
    assert found and found[0][1] is None
    assert "порт агента" in ports.describe(found)


def test_free_port_is_free_on_every_server():
    servers = [node([inbound(1, 443), inbound(2, 2053)]), node([inbound(3, 2083)], agent_port=2087)]
    assert ports.free_port(ProxyType.vless, "0.0.0.0", servers) == 2096
    # Свой же порт подключения при переносе не мешает.
    assert ports.free_port(ProxyType.vless, "0.0.0.0", servers, exclude_id=1, prefer=443) == 443
