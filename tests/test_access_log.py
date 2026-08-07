"""Разбор access-лога Xray для подсчёта устройств.

Формат лога проверен на настоящем Xray 26.x: адрес идёт сразу после «from»,
без префикса протокола. Ошибка здесь не видна снаружи — лимит устройств
просто молча не работал бы.
"""

import importlib.util
import os
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parent.parent / "agent" / "agent.py"


@pytest.fixture(scope="module")
def agent():
    os.environ.setdefault("AGENT_TOKEN", "test-token")
    spec = importlib.util.spec_from_file_location("vpn_agent", AGENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Настоящие строки, снятые с работающего Xray.
REAL_LINES = [
    "2026/08/07 21:28:39.492233 from 127.0.0.1:54342 accepted "
    "tcp:www.microsoft.com:443 [VLESS-REALITY >> DIRECT] email: live_user",
    "2026/08/07 21:28:41.749193 from 203.0.113.9:46410 accepted "
    "tcp:example.com:443 [VLESS-REALITY >> DIRECT] email: live_user",
    "2026/08/07 21:28:36.689798 from 127.0.0.1:43106 accepted "
    "tcp:127.0.0.1:10085 [api -> api]",
    "2026/08/07 21:28:44.001000 from [2001:db8::1]:51000 accepted "
    "tcp:example.org:443 [SS >> DIRECT] email: other_user",
]


def test_parses_real_lines(agent):
    matches = [agent._ACCESS_RE.match(line) for line in REAL_LINES]

    assert matches[0] and matches[0].group("ip") == "127.0.0.1"
    assert matches[0].group("email") == "live_user"
    assert matches[1] and matches[1].group("ip") == "203.0.113.9"
    # Служебные строки api-inbound не содержат email и не должны учитываться.
    assert matches[2] is None
    # IPv6 записывается в квадратных скобках.
    assert matches[3] and matches[3].group("ip") == "2001:db8::1"
    assert matches[3].group("email") == "other_user"


def test_ignores_lines_without_email(agent):
    assert agent._ACCESS_RE.match("2026/08/07 21:28:36 from 1.2.3.4:1 accepted tcp:x:443") is None
    assert agent._ACCESS_RE.match("мусор") is None
