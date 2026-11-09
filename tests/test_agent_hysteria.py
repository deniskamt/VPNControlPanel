"""Агент: недостающая Hysteria2 докачивается, повторная заливка не рвёт людей.

Было: на ноде без бинарника hysteria заливка конфига падала с 400 уже после
перезапуска Xray, панель повторяла её каждый цикл опроса — и Xray на этой
ноде перезапускался раз за разом, обрывая всех подключённых.
"""

import importlib.util
import io
import sys

import pytest
from fastapi.testclient import TestClient

from app.services import agent_source

AUTH = {"Authorization": "Bearer test-agent-token"}

FAKE_HYSTERIA = b"""#!/bin/sh
if [ "$1" = "version" ]; then echo "Version: v2.6.5"; exit 0; fi
exec sleep 30
"""

HYSTERIA_CONFIG = {
    "listen": ":443",
    "auth": {"type": "userpass", "userpass": {"u": "p"}},
    "trafficStats": {"listen": "127.0.0.1:1", "secret": "s"},
}


class _Alive:
    """Подставной «живой процесс» Xray."""

    def poll(self):
        return None


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN", "test-agent-token")
    monkeypatch.setenv("XRAY_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("XRAY_BIN", "/bin/true")
    monkeypatch.setenv("HYSTERIA_BIN", str(tmp_path / "bin" / "hysteria"))
    monkeypatch.setenv("HYSTERIA_CONFIG", str(tmp_path / "hysteria.json"))
    monkeypatch.setenv("HYSTERIA_STDOUT_LOG", str(tmp_path / "hysteria.log"))

    spec = importlib.util.spec_from_file_location("agent_hy_test", agent_source.AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_hy_test"] = module
    spec.loader.exec_module(module)

    restarts = []

    def fake_restart():
        restarts.append(True)
        module.xray.process = _Alive()

    monkeypatch.setattr(module.xray, "restart", fake_restart)
    monkeypatch.setattr(module.xray, "test_config", lambda path: "")
    monkeypatch.setattr(module.xray, "version", lambda: "26.3.27")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")

    downloads = []

    def fake_urlopen(url, timeout=0):
        downloads.append(url)
        return io.BytesIO(FAKE_HYSTERIA)

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)

    try:
        yield module, TestClient(module.app), restarts, downloads
    finally:
        module.hysteria.stop()
        sys.modules.pop("agent_hy_test", None)


def _push(client, config_hash="h1", hysteria=HYSTERIA_CONFIG):
    return client.post(
        "/config",
        json={"config": {"inbounds": [], "outbounds": []}, "hash": config_hash, "hysteria": hysteria},
        headers=AUTH,
    )


def test_missing_hysteria_is_downloaded_and_started(agent):
    module, client, restarts, downloads = agent

    response = _push(client)

    assert response.status_code == 200, response.text
    assert downloads == [
        "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64"
    ]
    assert module.hysteria.available and module.hysteria.running
    assert response.json()["hysteria_version"] == "v2.6.5"


def test_same_config_does_not_restart_anything(agent):
    module, client, restarts, _ = agent
    assert _push(client).status_code == 200
    hysteria_pid = module.hysteria.process.pid

    again = _push(client, config_hash="h2")

    assert again.status_code == 200
    assert restarts == [True]  # только первая заливка
    assert module.hysteria.process.pid == hysteria_pid
    # Отпечаток всё равно обновляется — иначе панель заливала бы снова.
    assert again.json()["config_hash"] == "h2"


def test_failed_download_is_reported_and_not_retried_every_cycle(agent, monkeypatch):
    module, client, restarts, _ = agent
    attempts = []

    def offline(url, timeout=0):
        attempts.append(url)
        raise OSError("github.com недоступен")

    monkeypatch.setattr(module.urllib.request, "urlopen", offline)

    first = _push(client)
    second = _push(client)

    assert first.status_code == 400
    assert "github.com" in first.json()["detail"]
    assert second.status_code == 400
    assert len(attempts) == 1
    # Xray перезапускался только при первой заливке — повтор его не трогает.
    assert restarts == [True]
    assert not (module.Path(module.HYSTERIA_BIN).with_name("hysteria.new")).exists()
