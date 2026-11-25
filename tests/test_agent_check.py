"""Зонд: агент проверяет серверы, подключаясь через них как пользователь.

Настоящая проверка поднимает настоящий Xray: локальный «VPN-сервер» и
локальный веб-сервер вместо интернета. Без ядра (переменная XRAY_TEST_BIN)
эти тесты пропускаются; проверка входных данных идёт всегда.
"""

import http.server
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

AUTH = {"Authorization": "Bearer check-token"}
XRAY = os.getenv("XRAY_TEST_BIN", "")
needs_xray = pytest.mark.skipif(
    not (XRAY and Path(XRAY).exists()), reason="нужен настоящий Xray в XRAY_TEST_BIN"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN", "check-token")
    monkeypatch.setenv("XRAY_BIN", XRAY or str(tmp_path / "no-xray"))
    monkeypatch.setenv("XRAY_CONFIG", str(tmp_path / "config.json"))  # зонду конфиг не нужен
    monkeypatch.setenv("XRAY_STDOUT_LOG", str(tmp_path / "stdout.log"))
    spec = importlib.util.spec_from_file_location(
        "agent_check", Path(__file__).resolve().parents[1] / "agent" / "agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_check"] = module
    spec.loader.exec_module(module)
    try:
        with TestClient(module.app) as client:
            yield module, client
    finally:
        sys.modules.pop("agent_check", None)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/204"):
            self.send_response(204)
            self.end_headers()
            return
        body = b"x" * 1_000_000
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def internet():
    """Локальный «интернет»: /204 и файл на мегабайт."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def vpn_server(tmp_path):
    """Настоящий Xray-сервер VLESS на локальном порту."""
    port, client_id = _free_port(), str(uuid.uuid4())
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                      "settings": {"clients": [{"id": client_id}], "decryption": "none"},
                      "streamSettings": {"network": "tcp"}}],
        "outbounds": [{"protocol": "freedom"}],
    }
    path = tmp_path / "server.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    process = subprocess.Popen([XRAY, "run", "-config", str(path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield port, client_id
    process.terminate()
    process.wait(timeout=5)


def _outbound(port: int, client_id: str) -> dict:
    return {"protocol": "vless", "settings": {"vnext": [{
        "address": "127.0.0.1", "port": port,
        "users": [{"id": client_id, "encryption": "none"}]}]},
        "streamSettings": {"network": "tcp", "security": "none"}}


def test_check_requires_token(agent):
    _, client = agent
    assert client.post("/check", json={"targets": []}).status_code == 401


def test_check_rejects_targets_without_outbound(agent):
    _, client = agent
    response = client.post("/check", json={"targets": [{"key": "a"}]}, headers=AUTH)
    assert response.status_code == 400


@needs_xray
def test_working_server_passes_tunnel_and_download(agent, internet, vpn_server):
    module, client = agent
    module.CHECK_URL = f"{internet}/204"
    module.CHECK_DOWNLOAD_URL = f"{internet}/file"
    port, client_id = vpn_server
    response = client.post("/check", headers=AUTH, json={"targets": [
        {"key": "ok", "outbound": _outbound(port, client_id),
         "host": "127.0.0.1", "port": port, "sni": "www.example.com"},
    ]})
    assert response.status_code == 200, response.text
    result = response.json()["results"][0]
    assert result["key"] == "ok"
    assert result["tunnel"]["ok"] is True, result
    assert result["download"]["ok"] is True and result["download"]["bytes"] >= 900_000, result
    # Сервер без TLS: рукопожатие не складывается — и это видно отдельно.
    assert result["tls"]["ok"] is False and result["tls"]["error"]


@needs_xray
def test_wrong_key_and_dead_server_fail(agent, internet, vpn_server):
    module, client = agent
    module.CHECK_URL = f"{internet}/204"
    module.CHECK_DOWNLOAD_URL = f"{internet}/file"
    port, _ = vpn_server
    dead = _free_port()
    response = client.post("/check", headers=AUTH, json={"targets": [
        {"key": "wrong-key", "outbound": _outbound(port, str(uuid.uuid4()))},
        {"key": "dead", "outbound": _outbound(dead, str(uuid.uuid4())),
         "host": "127.0.0.1", "port": dead, "sni": "www.example.com"},
    ]})
    assert response.status_code == 200, response.text
    by_key = {item["key"]: item for item in response.json()["results"]}
    for key in ("wrong-key", "dead"):
        assert by_key[key]["tunnel"]["ok"] is False, by_key[key]
        assert by_key[key]["download"]["ok"] is False
    assert by_key["dead"]["tls"]["error"] == "порт закрыт"


def test_reach_tells_open_closed_and_requires_token(agent):
    _, client = agent
    assert client.post("/reach", json={"targets": []}).status_code == 401
    listening = socket.socket()
    listening.bind(("127.0.0.1", 0))
    listening.listen()
    closed = _free_port()
    try:
        response = client.post("/reach", headers=AUTH, json={"targets": [
            {"host": "127.0.0.1", "port": listening.getsockname()[1]},
            {"host": "127.0.0.1", "port": closed},
        ]})
    finally:
        listening.close()
    assert response.status_code == 200, response.text
    states = [item["state"] for item in response.json()["results"]]
    assert states == ["open", "closed"]
    assert client.post("/reach", headers=AUTH, json={"targets": [{"host": "x"}]}).status_code == 400
