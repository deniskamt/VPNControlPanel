"""Флаги стран для названий серверов.

Клиентские приложения не знают про наше поле «страна» — они рисуют то, что
пришло в названии конфигурации. Флаг там появляется, только если это эмодзи,
поэтому двухбуквенный код превращаем в него сами.

Эмодзи флага — это две буквы-индикатора: «SE» → 🇸🇪.
"""

from typing import Optional

_INDICATOR_OFFSET = 0x1F1E6 - ord("A")

# Частые написания, которые администратор может ввести вместо кода.
ALIASES = {
    "РОССИЯ": "RU",
    "RUSSIA": "RU",
    "НИДЕРЛАНДЫ": "NL",
    "NETHERLANDS": "NL",
    "ГЕРМАНИЯ": "DE",
    "GERMANY": "DE",
    "ШВЕЦИЯ": "SE",
    "SWEDEN": "SE",
    "ФИНЛЯНДИЯ": "FI",
    "FINLAND": "FI",
    "США": "US",
    "USA": "US",
    "ФРАНЦИЯ": "FR",
    "FRANCE": "FR",
    "ТУРЦИЯ": "TR",
    "TURKEY": "TR",
    "ПОЛЬША": "PL",
    "POLAND": "PL",
    "ВЕЛИКОБРИТАНИЯ": "GB",
    "UK": "GB",
    "ЯПОНИЯ": "JP",
    "JAPAN": "JP",
    "СИНГАПУР": "SG",
    "SINGAPORE": "SG",
    "КАЗАХСТАН": "KZ",
    "ЛАТВИЯ": "LV",
    "ЛИТВА": "LT",
    "ЭСТОНИЯ": "EE",
    "ШВЕЙЦАРИЯ": "CH",
    "ИСПАНИЯ": "ES",
    "ИТАЛИЯ": "IT",
    "КАНАДА": "CA",
    "CANADA": "CA",
}


def country_flag(country: Optional[str]) -> str:
    """Эмодзи флага по коду страны. Пустая строка, если код непонятен."""
    if not country:
        return ""

    value = country.strip()
    # Если администратор уже вписал эмодзи — оставляем как есть.
    if any(0x1F1E6 <= ord(char) <= 0x1F1FF for char in value):
        return value

    code = ALIASES.get(value.upper(), value.upper())
    if len(code) != 2 or not code.isalpha() or not code.isascii():
        return ""

    return "".join(chr(ord(char) + _INDICATOR_OFFSET) for char in code)
