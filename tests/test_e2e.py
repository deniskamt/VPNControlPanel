"""Сквозной тест: API ботов, веб-панель, выдача подписки.

Требует живой Postgres. Запуск:

    TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/vpnpanel \\
        pytest tests/test_e2e.py

Без переменной тест пропускается, чтобы обычный прогон не требовал базы.
"""

import base64
import os

import pytest

# Переменные окружения выставляет tests/conftest.py — до импорта приложения.
pytestmark = pytest.mark.skipif(
    not os.getenv("TEST_DATABASE_URL"), reason="нужен TEST_DATABASE_URL с живым Postgres"
)


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


def test_quick_create_makes_working_inbound(client, inbound):
    """Шаблон должен давать подключение, готовое к работе без правок."""
    created = client.post(
        "/inbounds/quick",
        data={
            "preset": "vless_reality",
            "port": 8443,
            "masking_domain": "www.samsung.com",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text

    page = client.get("/inbounds").text
    # Tag берётся из названия шаблона: «VLESS + REALITY + Vision».
    assert "VLESS-REALITY-VISION" in page

    # Приватный ключ уходит в конфиг сервера, публичный там не нужен —
    # он живёт только в ссылке клиента. (В разметке кавычки экранированы,
    # поэтому ищем имена полей без них.)
    config = client.get("/nodes/1/config").text
    assert "privateKey" in config
    assert "publicKey" not in config


def test_node_config_page_shows_generated_config(client, inbound):
    page = client.get("/nodes/1/config")
    assert page.status_code == 200
    assert "config.json" in page.text
    assert "dokodemo-door" in page.text  # служебный api-inbound для статистики


def test_user_page_shows_qr_and_links(client, auth):
    """Подписку должно быть видно как ссылкой, так и QR-кодом."""
    users = client.get("/api/users", headers=auth).json()["users"]
    assert users

    listing = client.get("/users").text
    assert users[0]["username"] in listing

    detail = client.get("/users/1")
    assert detail.status_code == 200
    assert 'class="segno"' in detail.text  # инлайновый SVG с QR
    assert "vless://" in detail.text


def test_subscription_headers_carry_announce_and_support(client, auth, inbound):
    """Оформление профиля уезжает клиенту заголовками ответа подписки."""
    from base64 import b64decode

    saved = client.post(
        "/settings/subscription",
        data={
            "subscription_title": "МойVPN",
            "subscription_update_interval": "6",
            "support_url": "https://t.me/support_bot",
            "announce_url": "https://example.com/news",
            "announce": "Первая строка\nВторая строка",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303

    user = client.get("/api/user/user_12345", headers=auth).json()
    path = user["subscription_url"].replace("https://vpn.example.com", "")
    response = client.get(path, headers={"User-Agent": "v2rayTun/5.0"})

    assert response.status_code == 200
    # Кириллица и переносы строк в заголовок иначе не помещаются.
    assert b64decode(response.headers["profile-title"][len("base64:"):]).decode() == "МойVPN"
    announce = b64decode(response.headers["announce"][len("base64:"):]).decode()
    assert announce == "Первая строка\nВторая строка"
    assert response.headers["support-url"] == "https://t.me/support_bot"
    assert response.headers["announce-url"] == "https://example.com/news"
    assert response.headers["profile-update-interval"] == "6"


def test_empty_announce_is_not_sent(client, auth, inbound):
    """Пустое объявление не должно превращаться в пустую плашку в приложении."""
    client.post(
        "/settings/subscription",
        data={"subscription_title": "VPN", "subscription_update_interval": "12",
              "announce": "", "announce_url": "", "support_url": ""},
        follow_redirects=False,
    )
    user = client.get("/api/user/user_12345", headers=auth).json()
    path = user["subscription_url"].replace("https://vpn.example.com", "")
    response = client.get(path)

    assert "announce" not in response.headers
    assert "support-url" not in response.headers


def test_new_inbound_reaches_existing_users(client, auth, inbound):
    """Ровно жалоба администратора: создал протокол — а у людей его нет.

    Проверяется на настоящей базе: и выдача подключения существующим
    пользователям, и ключи протокола, без которых ссылку не собрать.
    """
    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_links", "proxies": {"vless": {}}, "expire": 0},
    )
    before = client.get("/api/user/user_links", headers=auth).json()
    assert set(before["proxies"]) == {"vless"}

    created = client.post(
        "/inbounds/quick",
        data={"preset": "shadowsocks_2022", "port": 9389},
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text

    after = client.get("/api/user/user_links", headers=auth).json()
    # Ключ Shadowsocks выдан сам, иначе подключение молча не появилось бы.
    assert "shadowsocks" in after["proxies"]
    assert any(link.startswith("ss://") for link in after["links"]), after["links"]


def test_obfuscated_inbound_reaches_both_subscriptions(client, auth, inbound):
    """Маскировка должна доезжать и обычной ссылкой (через extra), и JSON."""
    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_json", "proxies": {"vless": {}}, "expire": 0},
    )
    created = client.post(
        "/inbounds/quick",
        data={
            "preset": "vless_reality_xhttp",
            "port": 9443,
            "masking_domain": "www.samsung.com",
            "obfuscate": "1",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text

    token = client.get("/api/user/user_json", headers=auth).json()["subscription_url"]
    token = token.rstrip("/").split("/")[-1]

    links = client.get(f"/c/{token}?format=plain").text
    profiles = client.get(f"/c/{token}?format=json").json()

    import json as _json
    import urllib.parse as _url

    xhttp_links = [line for line in links.splitlines() if "type=xhttp" in line]
    assert xhttp_links, "маскированное подключение обязано быть в обычной подписке"
    params = dict(_url.parse_qsl(_url.urlparse(xhttp_links[0]).query))
    assert _json.loads(params["extra"])["xPaddingMethod"] == "tokenish"
    xhttp_profiles = [
        profile for profile in profiles
        if profile["outbounds"][0]["streamSettings"]["network"] == "xhttp"
    ]
    assert xhttp_profiles, "маскированное подключение обязано быть в JSON-подписке"
    block = xhttp_profiles[0]["outbounds"][0]["streamSettings"]["xhttpSettings"]
    assert block["mode"] == "stream-one"
    assert block["xPaddingMethod"] == "tokenish"


def test_grant_all_button_hands_out_an_older_inbound(client, auth, inbound):
    """Подключения, созданные до автоматической выдачи, раздаются кнопкой."""
    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_grant", "proxies": {"vless": {}},
              "inbounds": {"vless": ["VLESS-REALITY"]}, "expire": 0},
    )
    before = client.get("/api/user/user_grant", headers=auth).json()
    assert "trojan" not in before["proxies"]

    created = client.post(
        "/inbounds/create",
        data={
            "tag": "TROJAN-OLD", "protocol": "trojan", "port": 9444,
            "network": "tcp", "security": "tls", "listen": "0.0.0.0",
            "settings": '{"sni": "vpn.example.com"}',
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text

    # Снимаем подключение у пользователя, изображая созданное «до фикса».
    page = client.get("/inbounds").text
    assert "TROJAN-OLD" in page
    client.post(
        "/users/1/update",
        data={"user_status": "active", "inbound_ids": [1]},
        follow_redirects=False,
    )

    granted = client.post("/inbounds/2/grant-all", follow_redirects=False)
    assert granted.status_code == 303

    after = client.get("/api/user/user_grant", headers=auth).json()
    assert "trojan" in after["proxies"]
    assert any(link.startswith("trojan://") for link in after["links"]), after["links"]
