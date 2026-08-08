"""Расшифровка ошибок Xray.

Ядро сообщает о проблемах точно, но не подсказывает, что делать. Самая частая
причина — занятый порт: панель за nginx держит 443, и подключение на том же
порту не поднимется. Без подсказки это выглядит как «xray упал».
"""

import re
from typing import List, Optional, Tuple

# (что искать в сообщении, что посоветовать)
HINTS: List[Tuple[str, str]] = [
    (
        r"address already in use|bind: address already in use|failed to listen",
        "порт уже занят другой программой. Если панель стоит на этом же "
        "сервере, 443 держит её nginx. Либо перенесите подключение на "
        "свободный порт («Подключения» → «Настроить»), либо освободите 443 "
        "для VPN — маскировка под HTTPS на нём убедительнее, и сам Xray "
        "предупреждает о других портах",
    ),
    (
        r"permission denied",
        "нет прав на порт или файл. Порты ниже 1024 требуют root; "
        "проверьте также права на сертификат",
    ),
    (
        r"failed to initialize access logger|no such file or directory.*access",
        "Xray не может создать файл журнала — обновите агента на сервере: "
        "команда есть на этой странице, кнопка «Установка» → блок "
        "«Обновить уже установленного агента»",
    ),
    (
        r"certificate|tls: failed to find any PEM|cannot load|x509",
        "не читается сертификат: проверьте пути certificateFile и keyFile "
        "в параметрах подключения",
    ),
    (
        r"invalid.*private.*key|reality|shortid|short id",
        "не приняты параметры REALITY: приватный ключ должен быть из пары "
        "«xray x25519», а shortId — шестнадцатеричной строкой чётной длины",
    ),
    (
        r"invalid.*(uuid|id)|user id must be",
        "не принят идентификатор пользователя — перевыпустите ключи "
        "(«Отозвать подписку» в карточке пользователя)",
    ),
    (
        r"unknown.*(protocol|network)|unable to load type",
        "версия Xray на сервере не знает такой протокол или транспорт: "
        "обновите ядро на ноде или выберите другой шаблон",
    ),
    (
        r"method.*not.*support|invalid.*method|password.*length|key.*length",
        "не подходит шифрование Shadowsocks: у методов 2022-blake3-* ключ "
        "должен быть заданной длины — создайте подключение заново по шаблону",
    ),
]


def explain(message: Optional[str]) -> str:
    """Дописывает к сообщению ядра совет, если причина узнаваема."""
    if not message:
        return ""

    text = str(message)
    for pattern, hint in HINTS:
        # Регистр не приводим руками: в шаблонах встречаются и PEM, и x509,
        # и приведение текста к нижнему регистру ломало бы такие шаблоны.
        if re.search(pattern, text, re.IGNORECASE):
            return f"{text} — {hint}"
    return text
