"""Флаги стран в названиях серверов.

Клиентские приложения рисуют иконку страны только по эмодзи в названии
конфигурации: двухбуквенный код они не понимают и показывают глобус.
"""

import pytest

from app.services import flags
from app.services.flags import country_flag
from app.web import templates


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


def test_country_code_understands_names_and_emoji():
    assert flags.country_code("NL") == "NL"
    assert flags.country_code("Нидерланды") == "NL"
    assert flags.country_code("🇩🇪") == "DE"
    assert flags.country_code("бог знает что") == ""
    assert flags.country_code(None) == ""


def test_flag_is_rendered_as_image():
    # Эмодзи-флаг виден не в каждой системе, поэтому в панели — картинка.
    assert '<img class="flag" src="/static/flags/nl.svg"' in str(templates.flag("NL"))
    assert "eu.svg" in str(templates.flag("Евросоюз"))


def test_flag_falls_back_to_emoji_for_unknown_country():
    assert str(templates.flag("ZZ")) == "🇿🇿"
    assert str(templates.flag("")) == ""


def test_flag_text_replaces_only_the_flag():
    result = str(templates.flag_text("🇳🇱 Netherlands #1"))

    assert result.startswith('<img class="flag" src="/static/flags/nl.svg"')
    assert result.endswith(" Netherlands #1")


def test_flag_text_escapes_the_rest():
    assert "&lt;b&gt;" in str(templates.flag_text("🇳🇱 <b>"))


def test_flag_image_carries_its_own_size():
    # Размер задаётся в самой картинке: если css остался в кеше браузера,
    # флаг всё равно не растянется на всю строку.
    html = str(templates.flag("NL"))
    assert 'width="20"' in html and 'height="15"' in html


def test_asset_url_changes_with_the_file():
    url = templates.asset("css/app.css")
    assert url.startswith("/static/css/app.css?v=")
    # Несуществующий файл не должен ронять страницу.
    assert templates.asset("css/нет.css") == "/static/css/нет.css"


def test_status_badge_explains_itself():
    from app.models.enums import UserStatus

    badge = str(templates.status_badge(UserStatus.on_hold))
    # Значение из базы («on_hold») администратору ничего не говорит.
    assert "ожидание" in badge and "on_hold" not in badge
    assert "title=" in badge, "у значка нет пояснения"
    assert templates.status_title(UserStatus.limited) == "лимит"


def test_human_bytes_stays_short_in_tables():
    # Два знака после запятой удлиняли ячейку так, что строка переносилась.
    assert templates.human_bytes(200 * 1024**3) == "200 GB"
    assert templates.human_bytes(1536) == "1.5 KB"
    assert templates.human_bytes(512) == "512 B"
    assert templates.human_bytes(0) == "0 B"
