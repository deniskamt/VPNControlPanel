"""Сквозной тест: API ботов, веб-панель, выдача подписки.

Требует живой Postgres. Запуск:

    TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/vpnpanel \\
        pytest tests/test_e2e.py

Без переменной тест пропускается, чтобы обычный прогон не требовал базы.
"""

import base64
import os
import re

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


def test_unlimited_user_reports_zeroes_not_nulls(client, auth):
    """Боты считают expire и data_limit числами: `expire - now`, `used /
    data_limit`. Marzban отдавал в этих полях ноль, и null вместо него ронял
    бота на ровном месте — «unsupported operand type(s) for -: NoneType»."""
    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_forever", "proxies": {"vless": {}}},
    )

    user = client.get("/api/user/user_forever", headers=auth).json()
    assert user["expire"] == 0
    assert user["data_limit"] == 0

    listed = client.get("/api/users", headers=auth).json()["users"]
    forever = next(item for item in listed if item["username"] == "user_forever")
    assert forever["expire"] == 0 and forever["data_limit"] == 0

    token = user["subscription_url"].rsplit("/", 1)[-1]
    info = client.get(f"/c/{token}/info").json()
    assert info["expire"] == 0 and info["data_limit"] == 0

    by_token = client.get("/api/sub", headers=auth, params={"token": token}).json()
    assert by_token["expire"] == 0


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
    assert block["mode"] == "packet-up"
    assert block["xPaddingMethod"] == "tokenish"
    # Дробление соединений должно доехать вместе с маскировкой.
    assert block["extra"]["scStreamUpServerSecs"]


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


def test_subscription_page_shows_what_the_client_will_see(client, auth, inbound):
    """Раздел «Подписка»: строки должны совпадать с тем, что уходит клиенту."""
    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_view", "proxies": {"vless": {}},
              "inbounds": {"vless": ["VLESS-REALITY"]}, "expire": 0},
    )
    user = client.get("/api/user/user_view", headers=auth).json()

    page = client.get("/subscription").text
    assert "Конфигурации в подписке" in page
    # Сервер и подключение из фикстуры видны в списке.
    assert "VLESS-REALITY" in page
    assert "NL-1" in page


def test_subscription_page_explains_what_is_missing(client, auth, inbound):
    """Пустая строка подписки должна объясняться, а не оставлять гадать."""
    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_blocked", "proxies": {"vless": {}}, "expire": 0},
    )
    blocked = client.get("/api/user/user_blocked", headers=auth).json()

    # Закрываем пользователю единственный сервер — подписка должна опустеть,
    # а причина появиться в списке «не попало».
    users_page = client.get("/users").text
    assert "user_blocked" in users_page

    user_id = None
    import re
    for match in re.finditer(r'href="/users/(\d+)"', users_page):
        candidate = client.get(f"/users/{match.group(1)}").text
        if "user_blocked" in candidate.split("</h1>")[0]:
            user_id = match.group(1)
            break
    assert user_id, "не нашли карточку пользователя"

    client.post(f"/users/{user_id}/nodes", data={}, follow_redirects=False)
    page = client.get(f"/subscription?user_id={user_id}").text
    assert "Не попало в подписку" in page
    assert "закрыт для этого пользователя" in page


def test_subscription_host_can_be_created_and_changes_the_name(client, auth, inbound):
    """Настройка строки — то, ради чего раздел и нужен."""
    # Свой пользователь: у соседних тестов доступ к серверу мог быть закрыт.
    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_host", "proxies": {"vless": {}},
              "inbounds": {"vless": ["VLESS-REALITY"]}, "expire": 0},
    )
    username = "user_host"

    created = client.post(
        "/subscription/hosts/create",
        data={
            "inbound_id": 1,
            "node_id": 1,
            "remark": "{flag} Мой сервер — {protocol}",
            "address": "cdn.example.com",
            "port": 2053,
            "sni": "cdn.example.com",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text

    links = client.get(f"/api/user/{username}", headers=auth).json()["links"]
    assert any("cdn.example.com%3A2053" in link or "cdn.example.com:2053" in link
               for link in links), links
    assert any("%D0%9C%D0%BE%D0%B9%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80" in link
               for link in links), "название из настройки должно попасть в ссылку"


def _in_own_loop(coro_factory):
    """Выполнить работу с базой в отдельном движке и цикле.

    Пул основного движка принадлежит циклу TestClient — брать из него
    соединения через asyncio.run нельзя, asyncpg на этом ломается.
    """
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.core.config import settings

    async def run():
        engine = create_async_engine(settings.DATABASE_URL)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                return await coro_factory(session)
        finally:
            await engine.dispose()

    return asyncio.run(run())


def test_traffic_resets_by_strategy_and_unblocks_user(client, auth):
    """Лимит без сброса — мина: трафик копится вечно, и при очередном
    продлении человек навсегда остаётся limited и без связи на всех серверах.
    Marzban обнулял счётчик раз в период, панель должна так же."""
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from app.models import User
    from app.services.node_manager import apply_traffic_resets, enforce_limits

    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_heavy", "proxies": {"vless": {}},
              "data_limit": 200, "data_limit_reset_strategy": "month"},
    )

    def потратить(used: int, дней_назад: int):
        async def работа(session):
            user = await session.scalar(
                select(User).where(User.username == "user_heavy")
            )
            user.used_traffic = used
            user.traffic_reset_at = datetime.utcnow() - timedelta(days=дней_назад)
            await session.commit()
        _in_own_loop(работа)

    def прогнать():
        async def работа(session):
            сброшено = await apply_traffic_resets(session)
            await enforce_limits(session)
            return сброшено
        return _in_own_loop(работа)

    # Лимит потрачен, но месяц ещё не прошёл — сброса нет, доступ закрыт.
    потратить(used=250, дней_назад=10)
    assert прогнать() == 0
    assert client.get("/api/user/user_heavy", headers=auth).json()["status"] == "limited"

    # Прошёл месяц: трафик обнуляется, накопленное уходит в пожизненный
    # счётчик, а пользователь возвращается в строй сам.
    потратить(used=250, дней_назад=31)
    assert прогнать() == 1

    user = client.get("/api/user/user_heavy", headers=auth).json()
    assert user["used_traffic"] == 0
    assert user["lifetime_used_traffic"] >= 250
    assert user["status"] == "active"


def test_no_reset_strategy_leaves_traffic_alone(client, auth):
    """Стратегия no_reset (по умолчанию) ничего не обнуляет."""
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from app.models import User
    from app.services.node_manager import apply_traffic_resets

    client.post(
        "/api/user",
        headers=auth,
        json={"username": "user_forever_traffic", "proxies": {"vless": {}}},
    )

    async def работа(session):
        user = await session.scalar(
            select(User).where(User.username == "user_forever_traffic")
        )
        user.used_traffic = 999
        user.traffic_reset_at = datetime.utcnow() - timedelta(days=400)
        await session.commit()
        return await apply_traffic_resets(session)

    assert _in_own_loop(работа) == 0
    assert client.get("/api/user/user_forever_traffic",
                      headers=auth).json()["used_traffic"] == 999


def _subscription_names(client, auth):
    """Названия конфигураций в том порядке, в каком их получит приложение."""
    from urllib.parse import unquote

    user = client.get("/api/user/user_12345", headers=auth).json()
    path = user["subscription_url"].replace("https://vpn.example.com", "")
    response = client.get(path, headers={"User-Agent": "v2rayNG/1.8.5"})
    links = base64.b64decode(response.text).decode().splitlines()
    return [unquote(link.rsplit("#", 1)[-1]) for link in links]


def test_subscription_rows_can_be_interleaved(client, auth, inbound):
    """Две записи одного сервера должны уметь разойтись.

    Порядок в подписке сквозной: между записями одного сервера можно
    поставить запись другого — ради этого и делались стрелки.
    """
    second = client.post(
        "/nodes/create",
        data={
            "name": "DE-1",
            "address": "de1.example.com",
            "agent_host": "127.0.0.1",
            "agent_port": 9,
            "agent_token": "node-token",
            "country": "DE",
            "inbound_ids": [1],
        },
        follow_redirects=False,
    )
    assert second.status_code == 303, second.text

    # Номер пользователя берём со страницы: в Marzban-совместимом API его нет.
    page = client.get("/subscription").text
    user_id = re.search(r'value="(\d+)"[^>]*>\s*user_12345', page).group(1)

    created = client.post(
        "/subscription/hosts/create",
        data={
            "inbound_id": 1,
            "node_id": 1,
            "remark": "через фронт",
            "address": "front.example.com",
            "user_id": user_id,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text

    # Номер немецкого сервера — из его же строки: в форме «создать настройку»
    # он лежит рядом с подсказкой, к чему настройка применится.
    page = client.get(f"/subscription?user_id={user_id}").text
    german_id = re.search(
        r'name="node_id" value="(\d+)"[\s\S]{0,4000}?сервере DE-1', page
    ).group(1)

    names = _subscription_names(client, auth)
    assert "через фронт" in names, names
    # На сервере NL-1 две записи одного подключения, и они стоят рядом.
    mine = next(index for index, name in enumerate(names) if "Мой сервер" in name)
    front = names.index("через фронт")
    assert abs(mine - front) == 1, names

    # Двигаем немецкий сервер вниз — он должен встать между ними.
    moved = client.post(
        "/subscription/rows/move",
        data={
            "direction": "down",
            "node_id": german_id,
            "inbound_id": 1,
            "host_id": 0,
            "user_id": user_id,
        },
        follow_redirects=False,
    )
    assert moved.status_code == 303, moved.text

    names = _subscription_names(client, auth)
    mine = next(index for index, name in enumerate(names) if "Мой сервер" in name)
    german = next(index for index, name in enumerate(names) if "DE-1" in name)
    front = names.index("через фронт")
    assert mine < german < front, names


def test_pages_show_flag_images(client, inbound):
    """Флаг в панели — картинка: эмодзи рисуется не в каждой системе."""
    page = client.get("/nodes").text
    assert '<img class="flag" src="/static/flags/nl.svg"' in page
    assert client.get("/static/flags/nl.svg").status_code == 200

    # В названии конфигурации флаг тоже подменяется картинкой, а сам текст
    # уходит клиенту с эмодзи — иначе приложение не нарисует иконку страны.
    assert "/static/flags/de.svg" in client.get("/subscription").text
