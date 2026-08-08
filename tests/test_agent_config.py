"""Приём конфига агентом: что доезжает до панели вместо «xray упал».

Ядро здесь подменено скриптом-заглушкой, который ведёт себя как Xray в трёх
интересных случаях: конфиг не проходит проверку, конфиг проходит проверку но
не стартует (занятый порт), конфиг в порядке. Поведение заглушки списано с
живого прогона на настоящем ядре 26.3.27.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

AUTH = {"Authorization": "Bearer cfg-token"}

# Заглушка ядра: «run -test» ругается на протокол broken-protocol,
# настоящий запуск падает на порту 9999 (как на занятом), иначе живёт.
FAKE_XRAY = """#!/bin/sh
if [ "$1" = "version" ]; then
  echo "Xray 26.3.27 (Xray, Penetrates Everything.) fake"
  exit 0
fi
config=""
test_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    -test) test_only=1 ;;
    -config) shift; config="$1" ;;
  esac
  shift
done
case "$config" in
  *.json) ;;
  *) echo "Failed to start: main: core: Failed to get format of $config"; exit 23 ;;
esac
if grep -q broken-protocol "$config"; then
  echo "Xray 26.3.27 (Xray, Penetrates Everything.) fake"
  echo "Failed to start: main: infra/conf: unknown config id: broken-protocol"
  exit 23
fi
if [ "$test_only" = "1" ]; then
  echo "Configuration OK."
  exit 0
fi
if grep -q '"port": 9999' "$config"; then
  echo "Failed to start: app/proxyman/inbound: failed to listen TCP on 9999 >"\\
" listen tcp 0.0.0.0:9999: bind: address already in use"
  exit 23
fi
sleep 300
"""


def _config(port: int = 1080, protocol: str = "socks", access: str = "") -> dict:
    return {
        "log": {"loglevel": "warning", "access": access},
        "inbounds": [{"tag": "in", "port": port, "protocol": protocol}],
        "outbounds": [{"protocol": "freedom"}],
    }


@pytest.fixture
def node(tmp_path, monkeypatch):
    """Агент с заглушкой вместо ядра и рабочим конфигом на диске."""
    binary = tmp_path / "xray"
    binary.write_text(FAKE_XRAY, encoding="utf-8")
    binary.chmod(0o755)

    live = tmp_path / "config.json"
    live.write_text(json.dumps(_config()), encoding="utf-8")

    monkeypatch.setenv("AGENT_TOKEN", "cfg-token")
    monkeypatch.setenv("XRAY_BIN", str(binary))
    monkeypatch.setenv("XRAY_CONFIG", str(live))
    monkeypatch.setenv("XRAY_STDOUT_LOG", str(tmp_path / "stdout.log"))
    monkeypatch.setenv("XRAY_ACCESS_LOG", str(tmp_path / "access.log"))

    spec = importlib.util.spec_from_file_location(
        "agent_cfg", Path(__file__).resolve().parents[1] / "agent" / "agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_cfg"] = module
    spec.loader.exec_module(module)

    try:
        # Контекст поднимает Xray на исправном конфиге, как при старте сервиса.
        with TestClient(module.app) as client:
            yield module, client, tmp_path
    finally:
        module.xray.stop()
        sys.modules.pop("agent_cfg", None)


def test_broken_config_never_touches_the_running_xray(node):
    module, client, tmp_path = node
    live = tmp_path / "config.json"
    before = live.read_text(encoding="utf-8")
    pid_before = module.xray.process.pid

    response = client.post(
        "/config",
        json={"config": _config(protocol="broken-protocol"), "hash": "h"},
        headers=AUTH,
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    # Панели уезжает то, что сказало ядро, а не «xray упал».
    assert "unknown config id: broken-protocol" in detail
    # Приветствие ядра отфильтровано и не вытесняет причину.
    assert "Penetrates Everything" not in detail
    # Рабочий конфиг цел, Xray продолжает работать тем же процессом.
    assert live.read_text(encoding="utf-8") == before
    assert module.xray.running
    assert module.xray.process.pid == pid_before


def test_rejected_config_is_left_on_disk_for_a_manual_check(node):
    module, client, tmp_path = node
    client.post(
        "/config",
        json={"config": _config(protocol="broken-protocol"), "hash": "h"},
        headers=AUTH,
    )

    rejected = tmp_path / "config.rejected.json"
    assert rejected.exists()
    # Имя обязано кончаться на .json: формат ядро определяет по расширению и
    # на «config.json.rejected» браковало любой конфиг.
    assert rejected.name.endswith(".json")
    assert json.loads(rejected.read_text(encoding="utf-8"))["inbounds"][0][
        "protocol"
    ] == "broken-protocol"
    # И путь к нему назван в ошибке — иначе его никто не найдёт.
    assert str(rejected) in client.post(
        "/config",
        json={"config": _config(protocol="broken-protocol"), "hash": "h"},
        headers=AUTH,
    ).json()["detail"]


def test_busy_port_is_caught_at_start_and_rolled_back(node):
    """Проверка конфига порты не занимает — такое ловится только запуском."""
    module, client, tmp_path = node
    live = tmp_path / "config.json"
    before = live.read_text(encoding="utf-8")

    response = client.post(
        "/config", json={"config": _config(port=9999), "hash": "h"}, headers=AUTH
    )

    assert response.status_code == 400
    assert "address already in use" in response.json()["detail"]
    # Нода не осталась лежать: конфиг откачен, ядро снова работает.
    assert live.read_text(encoding="utf-8") == before
    assert module.xray.running


def test_good_config_is_applied_and_leaves_no_leftovers(node):
    module, client, tmp_path = node

    response = client.post(
        "/config", json={"config": _config(port=1081), "hash": "hash-1081"}, headers=AUTH
    )

    assert response.status_code == 200
    assert response.json()["config_hash"] == "hash-1081"
    applied = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert applied["inbounds"][0]["port"] == 1081
    assert not (tmp_path / "config.rejected.json").exists()


def test_access_log_directory_is_created(node):
    """Xray не стартует, если каталог под access-лог не существует."""
    module, client, tmp_path = node
    access = tmp_path / "logs" / "deep" / "access.log"

    response = client.post(
        "/config",
        json={"config": _config(port=1082, access=str(access)), "hash": "h"},
        headers=AUTH,
    )

    assert response.status_code == 200
    assert access.exists()
    assert module.xray.access_log == access


def test_panel_turns_the_busy_port_answer_into_advice(node):
    """Связка целиком: ответ агента проходит через explain() панели."""
    from app.services.xray_errors import explain

    module, client, _ = node
    detail = client.post(
        "/config", json={"config": _config(port=9999), "hash": "h"}, headers=AUTH
    ).json()["detail"]

    advice = explain(f"агент вернул 400: {detail}")
    assert "порт уже занят" in advice
    assert "9999" in advice
