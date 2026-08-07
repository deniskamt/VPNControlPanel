"""Разбор конфигурации: пустые и «грязные» значения не должны ронять старт."""

import pytest

from app.core.config import Settings


def make(**overrides) -> Settings:
    # _env_file=None — читаем только переданное, а не .env разработчика.
    return Settings(_env_file=None, **overrides)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", []),
        ("123456789", [123456789]),
        ("123456789,987654321", [123456789, 987654321]),
        (" 123456789 , 987654321 ", [123456789, 987654321]),
        ("123456789,,", [123456789]),
        ("123456789,не-число", [123456789]),
    ],
)
def test_telegram_admin_ids_parsing(raw, expected):
    assert make(TELEGRAM_ADMIN_IDS=raw).telegram_admin_ids == expected


@pytest.mark.parametrize(
    "raw",
    [
        "postgres://u:p@h:5432/db",
        "postgresql://u:p@h:5432/db",
        "postgresql+asyncpg://u:p@h:5432/db",
    ],
)
def test_database_url_normalized_to_async_driver(raw):
    settings = make(DATABASE_URL=raw)
    assert settings.DATABASE_URL == "postgresql+asyncpg://u:p@h:5432/db"
    assert settings.sync_database_url == "postgresql://u:p@h:5432/db"


def test_urls_lose_trailing_slash():
    settings = make(
        PANEL_URL="https://panel.example.com/",
        SUBSCRIPTION_BASE_URL="https://vpn.example.com/",
        SUBSCRIPTION_PATH="/c/",
    )
    assert settings.PANEL_URL == "https://panel.example.com"
    assert settings.SUBSCRIPTION_PATH == "c"
    assert settings.subscription_url("TOKEN") == "https://vpn.example.com/c/TOKEN"


def test_subscription_base_falls_back_to_panel_url():
    settings = make(PANEL_URL="https://panel.example.com", SUBSCRIPTION_BASE_URL="")
    assert settings.subscription_base == "https://panel.example.com"


def test_subscription_secret_falls_back_to_secret_key():
    assert make(SECRET_KEY="abc", SUBSCRIPTION_SECRET="").subscription_secret == "abc"
    assert make(SECRET_KEY="abc", SUBSCRIPTION_SECRET="xyz").subscription_secret == "xyz"
