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


def test_country_options_are_sorted_and_complete():
    """Список для выпадающего меню: без дублей, с флагом у каждой страны."""
    from app.services.flags import COUNTRIES, country_options

    options = country_options()
    codes = [code for code, _, _ in options]

    assert len(codes) == len(set(codes)), "в списке есть дубликаты кодов"
    assert len(codes) == len({code for code, _ in COUNTRIES})
    assert all(emoji for _, emoji, _ in options), "у какой-то страны нет флага"

    names = [name.lower() for _, _, name in options]
    assert names == sorted(names), "список должен идти по алфавиту"


def test_country_options_keep_unknown_current_value():
    """Значение, вписанное до появления выбора, не должно потеряться."""
    from app.services.flags import country_options

    options = country_options("QQ")
    assert options[0][0] == "QQ"

    # Уже известная страна не дублируется.
    assert [code for code, _, _ in country_options("SE")].count("SE") == 1
