"""Флаги стран в названиях серверов.

Клиентские приложения рисуют иконку страны только по эмодзи в названии
конфигурации: двухбуквенный код они не понимают и показывают глобус.
"""

import pytest

from app.services.flags import country_flag


@pytest.mark.parametrize(
    "code, expected",
    [
        ("SE", "🇸🇪"),
        ("se", "🇸🇪"),
        (" fi ", "🇫🇮"),
        ("RU", "🇷🇺"),
        ("NL", "🇳🇱"),
    ],
)
def test_two_letter_code_becomes_flag(code, expected):
    assert country_flag(code) == expected


@pytest.mark.parametrize("name, expected", [("Швеция", "🇸🇪"), ("Finland", "🇫🇮")])
def test_common_country_names_recognised(name, expected):
    assert country_flag(name) == expected


def test_existing_emoji_kept_as_is():
    assert country_flag("🇳🇱") == "🇳🇱"


@pytest.mark.parametrize("value", ["", None, "Швеция-Стокгольм", "S", "12"])
def test_unrecognised_values_give_nothing(value):
    assert country_flag(value) == ""
