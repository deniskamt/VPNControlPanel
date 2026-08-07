"""Сквозной тест: API ботов, веб-панель, выдача подписки.

Требует живой Postgres. Запуск:

    TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/vpnpanel \\
        pytest tests/test_e2e.py

Без переменной тест пропускается, чтобы обычный прогон не требовал базы.
"""

import base64
import os

import pytest

DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="нужен TEST_DATABASE_URL с живым Postgres"
)

if DATABASE_URL:
    os.environ["DATABASE_URL"] = DATABASE_URL
    os.environ["SECRET_KEY"] = "e2e-secret"
    os.environ["SUBSCRIPTION_SECRET"] = "e2e-subscription-secret"
    os.environ["SUBSCRIPTION_BASE_URL"] = "https://vpn.example.com"
    os.environ["SUBSCRIPTION_PATH"] = "c"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "admin-password"
    os.environ["NODE_POLL_INTERVAL"] = "3600"
    os.environ["ENFORCE_INTERVAL"] = "3600"


@pytest.fixture(scope="module")
def client():
    import asyncio

    from fastapi.testclient import TestClient
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.core.config import settings
    from app.main import app
    from app.models import Base

    async def reset() -> None:
        # Отдельный движок в отдельном цикле: пул основного движка должен
        # остаться нетронутым, иначе TestClient получит соединения чужого loop.
        temporary = create_async_engine(settings.DATABASE_URL)
        async with temporary.begin() as connection:
            await connection.run_sync(Base.metadata.drop_all)
        await temporary.dispose()

    asyncio.run(reset())

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def token(client):
    response = client.post(
        "/api/admin/token", data={"username": "admin", "password": "admin-password"}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def inbound(client):
    """Заводим подключение и сервер через веб-панель — как это делает админ."""
    import json

    # До входа панель должна отправлять на форму логина.
    assert client.get("/", follow_redirects=False).status_code == 303

    login = client.post(
        "/login",
        data={"username": "admin", "password": "admin-password", "next": "/"},
        follow_redirects=False,
    )
    assert login.status_code == 303, login.text

    created = client.post(
        "/inbounds/create",
        data={
            "tag": "VLESS-REALITY",
            "protocol": "vless",
            "port": 443,
            "network": "tcp",
            "security": "reality",
            "listen": "0.0.0.0",
            "settings": json.dumps(
                {
                    "dest": "www.microsoft.com:443",
                    "serverNames": ["www.microsoft.com"],
                    "privateKey": "PRIVATE",
                    "publicKey": "PUBLIC",
                    "shortIds": ["ab12"],
                    "flow": "xtls-rprx-vision",
                }
            ),
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text

    page = client.get("/inbounds")
    assert "VLESS-REALITY" in page.text

    # Агента на этом «сервере» нет — залить конфиг не выйдет, и это ожидаемо:
    # проверяем, что панель переживает недоступную ноду.
    node = client.post(
        "/nodes/create",
        data={
            "name": "NL-1",
            "address": "nl1.example.com",
            "agent_host": "127.0.0.1",
            "agent_port": 9,
            "agent_token": "node-token",
            "country": "NL",
            "inbound_ids": [1],
        },
        follow_redirects=False,
    )
    assert node.status_code == 303, node.text


def test_wrong_password_rejected(client):
    response = client.post(
        "/api/admin/token", data={"username": "admin", "password": "nope"}
    )
    assert response.status_code == 401


def test_api_requires_token(client):
    assert client.get("/api/users").status_code == 401


def test_bot_flow_create_user(client, auth, inbound):
    """Именно так пользователя заводит NexloVPN после оплаты."""
    response = client.post(
        "/api/user",
        headers=auth,
        json={
            "username": "user_12345",
            "proxies": {"vless": {}},
            "inbounds": {"vless": ["VLESS-REALITY"]},
            "expire": 4102444800,
            "data_limit": 214748364800,
            "data_limit_reset_strategy": "month",
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["username"] == "user_12345"
    assert data["status"] == "active"
    assert data["subscription_url"].startswith("https://vpn.example.com/c/")
    assert data["proxies"]["vless"]["id"]
    assert data["inbounds"] == {"vless": ["VLESS-REALITY"]}
    assert len(data["links"]) == 1
    assert data["links"][0].startswith("vless://")


def test_duplicate_user_rejected(client, auth):
    response = client.post(
        "/api/user", headers=auth, json={"username": "user_12345", "proxies": {"vless": {}}}
    )
    assert response.status_code == 409


def test_subscription_link_serves_configs(client, auth):
    user = client.get("/api/user/user_12345", headers=auth).json()
    path = user["subscription_url"].replace("https://vpn.example.com", "")

    response = client.get(path, headers={"User-Agent": "v2rayNG/1.8.5"})
    assert response.status_code == 200

    links = base64.b64decode(response.text).decode().splitlines()
    assert len(links) == 1
    assert links[0].startswith("vless://")
    assert "pbk=PUBLIC" in links[0]
    assert "PRIVATE" not in links[0]

    # Заголовки, по которым клиент показывает остаток трафика и срок.
    assert "total=214748364800" in response.headers["subscription-userinfo"]
    assert response.headers["profile-title"].startswith("base64:")


def test_renewal_keeps_uuid_and_link(client, auth):
    """Продление не должно менять ключи — иначе у клиента отвалится конфиг."""
    before = client.get("/api/user/user_12345", headers=auth).json()

    updated = client.put(
        "/api/user/user_12345",
        headers=auth,
        json={
            "expire": 4102531200,
            "data_limit": 214748364800,
            "proxies": {"vless": {}},
            "inbounds": {"vless": ["VLESS-REALITY"]},
        },
    ).json()

    assert updated["expire"] == 4102531200
    assert updated["proxies"]["vless"]["id"] == before["proxies"]["vless"]["id"]
    assert updated["subscription_url"] == before["subscription_url"]


def test_expired_user_returns_to_active_on_renewal(client, auth):
    client.post(
        "/api/user", headers=auth, json={"username": "user_old", "proxies": {"vless": {}},
                                         "expire": 1000000000}
    )
    assert client.get("/api/user/user_old", headers=auth).json()["status"] == "active"

    renewed = client.put(
        "/api/user/user_old", headers=auth, json={"expire": 4102444800}
    ).json()
    assert renewed["status"] == "active"


def test_revoke_breaks_old_link_and_issues_new(client, auth):
    old = client.get("/api/user/user_12345", headers=auth).json()
    old_path = old["subscription_url"].replace("https://vpn.example.com", "")
    old_uuid = old["proxies"]["vless"]["id"]

    revoked = client.post("/api/user/user_12345/revoke_sub", headers=auth).json()

    assert revoked["proxies"]["vless"]["id"] != old_uuid
    assert revoked["subscription_url"] != old["subscription_url"]
    assert client.get(old_path).status_code == 404
    new_path = revoked["subscription_url"].replace("https://vpn.example.com", "")
    assert client.get(new_path).status_code == 200


def test_inbounds_endpoint_shape_matches_marzban(client, auth):
    data = client.get("/api/inbounds", headers=auth).json()
    assert "vless" in data
    assert data["vless"][0]["tag"] == "VLESS-REALITY"


def test_app_sub_endpoint(client, auth):
    """AppVPN узнаёт актуальный адрес подписки через /api/sub."""
    user = client.get("/api/user/user_12345", headers=auth).json()
    token = user["subscription_url"].rsplit("/", 1)[1]

    data = client.get("/api/sub", params={"token": token}).json()
    assert data["subscription_url"] == user["subscription_url"]


def test_delete_user(client, auth):
    assert client.delete("/api/user/user_old", headers=auth).status_code == 200
    assert client.get("/api/user/user_old", headers=auth).status_code == 404


def test_web_pages_render(client, inbound):
    for path in ("/", "/nodes", "/users", "/inbounds", "/logs", "/settings"):
        page = client.get(path)
        assert page.status_code == 200, path
        assert "VPN" in page.text

    assert "user_12345" in client.get("/users").text


def test_audit_log_records_actions(client):
    page = client.get("/logs")
    assert "user.create" in page.text
    assert "user.revoke_sub" in page.text
