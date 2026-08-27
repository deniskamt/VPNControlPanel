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
    "ЕВРОСОЮЗ": "EU",
    "ЕВРОПА": "EU",
    "EUROPE": "EU",
}


# Страны для выпадающего списка в форме сервера: код и название.
# Эмодзи не храним — оно выводится из кода, поэтому разойтись они не могут.
# «EU» — не страна, но флаг из него собирается тем же способом, и в названии
# сервера он читается как «где-то в Европе», когда точное место не важно.
COUNTRIES = [
    ("EU", "Евросоюз"),
    ("NL", "Нидерланды"),
    ("DE", "Германия"),
    ("SE", "Швеция"),
    ("FI", "Финляндия"),
    ("NO", "Норвегия"),
    ("DK", "Дания"),
    ("GB", "Великобритания"),
    ("FR", "Франция"),
    ("ES", "Испания"),
    ("IT", "Италия"),
    ("PT", "Португалия"),
    ("CH", "Швейцария"),
    ("AT", "Австрия"),
    ("BE", "Бельгия"),
    ("IE", "Ирландия"),
    ("PL", "Польша"),
    ("CZ", "Чехия"),
    ("SK", "Словакия"),
    ("HU", "Венгрия"),
    ("RO", "Румыния"),
    ("BG", "Болгария"),
    ("EE", "Эстония"),
    ("LV", "Латвия"),
    ("LT", "Литва"),
    ("MD", "Молдова"),
    ("UA", "Украина"),
    ("RU", "Россия"),
    ("BY", "Беларусь"),
    ("KZ", "Казахстан"),
    ("AM", "Армения"),
    ("GE", "Грузия"),
    ("AZ", "Азербайджан"),
    ("TR", "Турция"),
    ("CY", "Кипр"),
    ("IL", "Израиль"),
    ("AE", "ОАЭ"),
    ("US", "США"),
    ("CA", "Канада"),
    ("BR", "Бразилия"),
    ("AR", "Аргентина"),
    ("JP", "Япония"),
    ("KR", "Южная Корея"),
    ("SG", "Сингапур"),
    ("HK", "Гонконг"),
    ("TW", "Тайвань"),
    ("IN", "Индия"),
    ("ID", "Индонезия"),
    ("VN", "Вьетнам"),
    ("TH", "Таиланд"),
    ("AU", "Австралия"),
    ("NZ", "Новая Зеландия"),
    ("ZA", "ЮАР"),
    ("EG", "Египет"),
    ("MX", "Мексика"),
    ("CL", "Чили"),
    ("RS", "Сербия"),
]


def country_options(current: Optional[str] = None):
    """Список для выпадающего меню: (код, эмодзи, название).

    Порядок — по названию страны, чтобы искать глазами было удобно.
    Если у сервера уже стоит значение, которого нет в списке (например,
    вписанное до появления выбора), оно добавляется первым — иначе при
    сохранении формы настройка потерялась бы.
    """
    seen = set()
    options = []

    for code, name in COUNTRIES:
        if code in seen:
            continue
        seen.add(code)
        options.append((code, country_flag(code), name))

    options.sort(key=lambda item: item[2].lower())

    value = (current or "").strip()
    if value and value.upper() not in seen:
        options.insert(0, (value, country_flag(value), value))

    return options


def country_code(country: Optional[str]) -> str:
    """Двухбуквенный код по значению из карточки сервера.

    Значение приходит откуда угодно: код, русское название, а иногда и сам
    эмодзи флага — его разбираем обратно в буквы. Пустая строка, если понять
    не удалось.
    """
    if not country:
        return ""

    value = country.strip()
    letters = [
        chr(ord(char) - _INDICATOR_OFFSET)
        for char in value
        if 0x1F1E6 <= ord(char) <= 0x1F1FF
    ]
    if len(letters) == 2:
        return "".join(letters).upper()

    code = ALIASES.get(value.upper(), value.upper())
    if len(code) == 2 and code.isalpha() and code.isascii():
        return code
    return ""


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
