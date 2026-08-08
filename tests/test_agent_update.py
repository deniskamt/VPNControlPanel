"""Самообновление агента: что он принимает, а что отвергает.

Агент подменяет собственный файл, поэтому в тестах он загружается из копии в
tmp_path — иначе успешный тест перезаписал бы agent/agent.py в репозитории.
"""

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.services import agent_source

AUTH = {"Authorization": "Bearer test-agent-token"}


@pytest.fixture
def agent(tmp_path, monkeypatch):
    """Агент, загруженный из копии файла, с заглушкой вместо выхода."""
    monkeypatch.setenv("AGENT_TOKEN", "test-agent-token")

    copy = tmp_path / "agent.py"
    shutil.copy(agent_source.AGENT_PATH, copy)

    spec = importlib.util.spec_from_file_location("agent_under_test", copy)
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_under_test"] = module
    spec.loader.exec_module(module)

    exits = []
    # Настоящий обработчик зовёт os._exit и убил бы pytest.
    monkeypatch.setattr(module, "_exit_for_restart", lambda: exits.append(True))

    try:
        yield module, TestClient(module.app), copy, exits
    finally:
        sys.modules.pop("agent_under_test", None)


def test_update_replaces_own_code_and_restarts(agent):
    module, client, path, exits = agent
    new_source = agent_source.read_source().replace(
        "AGENT_VERSION = ", "AGENT_VERSION = 99  # ", 1
    )

    response = client.post(
        "/update", json={"source": new_source, "version": 99}, headers=AUTH
    )

    assert response.status_code == 200
    assert response.json()["restarting"] is True
    assert path.read_text(encoding="utf-8") == new_source
    # Прежний файл остаётся рядом: есть куда вернуться руками.
    assert path.with_suffix(".py.bak").exists()
    assert exits == [True]


def test_update_rejects_broken_python(agent):
    module, client, path, exits = agent
    before = path.read_text(encoding="utf-8")

    response = client.post(
        "/update",
        json={"source": "class XrayProcess:\n  def oops(\n", "version": 3},
        headers=AUTH,
    )

    assert response.status_code == 400
    assert "не компилируется" in response.json()["detail"]
    # Главное: файл не тронут и агент не перезапускается.
    assert path.read_text(encoding="utf-8") == before
    assert exits == []


def test_update_rejects_something_that_is_not_the_agent(agent):
    module, client, path, exits = agent
    before = path.read_text(encoding="utf-8")

    response = client.post(
        "/update", json={"source": "print('hello')\n", "version": 3}, headers=AUTH
    )

    assert response.status_code == 400
    assert "не похож на агента" in response.json()["detail"]
    assert path.read_text(encoding="utf-8") == before
    assert exits == []


def test_update_rejects_empty_source(agent):
    module, client, path, exits = agent
    response = client.post("/update", json={"source": "   "}, headers=AUTH)
    assert response.status_code == 400
    assert exits == []


def test_update_needs_the_token(agent):
    module, client, path, exits = agent
    before = path.read_text(encoding="utf-8")

    response = client.post(
        "/update", json={"source": agent_source.read_source(), "version": 3}
    )

    assert response.status_code == 401
    assert path.read_text(encoding="utf-8") == before
    assert exits == []


def test_health_reports_agent_version(agent):
    module, client, _, _ = agent
    body = client.get("/health", headers=AUTH).json()
    assert body["agent_version"] == module.AGENT_VERSION
    assert body["agent_version"] == agent_source.bundled_version()
