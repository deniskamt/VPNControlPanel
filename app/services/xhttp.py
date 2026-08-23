"""Транспорт XHTTP: режимы и усиленная маскировка.

XHTTP умеет прятать служебные поля (порядковый номер куска, идентификатор
сессии, добивку до случайной длины) в обычных местах HTTP-запроса — в
заголовках, query-параметрах или cookie. Снаружи это выглядит как загрузка
файла в чужой веб-сервис.

Значения подбираются случайно для каждого подключения, и это не украшение:
в интернете гуляет один и тот же пример конфига с фиксированными
«X-Upload-Token» и «chunk_id», а повторяющийся у тысяч серверов набор имён
сам становится приметой. Панель выдаёт каждому подключению свой набор.

Какие значения ядро принимает — проверено запуском Xray 26.7.28:
  * xPaddingPlacement: header, query, queryInHeader, cookie
    (path и none ядро отвергает);
  * xPaddingMethod: только tokenish;
  * seqPlacement: query, header, path, cookie;
  * sessionIDPlacement: header, query.
"""

import random
from typing import Any, Dict, List

# Режимы XHTTP. stream-one быстрее остальных на замерах и работает под
# REALITY; packet-up нужен за CDN, который не пропускает длинные ответы.
MODES: List[str] = ["stream-one", "stream-up", "packet-up", "auto"]
DEFAULT_MODE = "stream-one"

# Дробление соединений — то, ради чего XHTTP и нужен.
#
# Длинное TCP-соединение к зарубежному серверу зависает после ~16 КБ. Под
# REALITY режим «auto» выбирает stream-one, то есть один длинный поток, — и
# упирается в тот же порог, что и обычный VLESS. Поэтому режим задаём
# явно: packet-up отправляет аплинк отдельными POST'ами, scStreamUpServerSecs
# периодически пересоздаёт даунлинк, а xmux ограничивает, сколько раз можно
# переиспользовать одно соединение.
#
# Проверено на живых ядрах: эти поля понимают и 25.6.8, и 26.3.27, и 26.7.28
# (в отличие от маскировочных, несовместимых между версиями), а скорость
# такая же, как без них.
ANTI_FREEZE = {
    "scMaxEachPostBytes": "100000-200000",
    "scMinPostsIntervalMs": "10-30",
    "scStreamUpServerSecs": "20-80",
    "xmux": {
        "maxConcurrency": "8-16",
        "maxConnections": 0,
        "cMaxReuseTimes": "16-32",
        "hMaxRequestTimes": "400-600",
        "hKeepAlivePeriod": 0,
    },
}


def anti_freeze_settings() -> Dict[str, Any]:
    """Копия параметров дробления — чтобы вызывающий мог их править."""
    settings = dict(ANTI_FREEZE)
    settings["xmux"] = dict(ANTI_FREEZE["xmux"])
    return settings


# Поля, которые панель передаёт в xhttpSettings как есть.
OBFUSCATION_KEYS = (
    "xPaddingBytes",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingMethod",
    "xPaddingPlacement",
    "xPaddingObfsMode",
    "seqKey",
    "seqPlacement",
    "sessionIDKey",
    "sessionIDPlacement",
    "sessionIDLength",
)

# Имена, которые не выглядят инородно в запросе к обычному веб-сервису.
_HEADER_NAMES = [
    "X-Client-Ver", "X-Request-Id", "X-Trace-Id", "X-Correlation-Id",
    "X-Upload-Token", "X-Session-Token", "X-Device-Id", "X-Api-Version",
]
_QUERY_NAMES = [
    "chunk", "chunk_id", "seq", "offset", "part", "idx", "frame", "segment",
]
_TOKEN_NAMES = ["token", "session", "sid", "upload_id", "tid"]

_PAD_PLACEMENTS = ["header", "query", "queryInHeader", "cookie"]
_SEQ_PLACEMENTS = ["query", "header", "cookie"]
_SESSION_PLACEMENTS = ["header", "query"]


def generate_obfuscation() -> Dict[str, Any]:
    """Свой набор маскировочных параметров для одного подключения."""
    pad_placement = random.choice(_PAD_PLACEMENTS)
    seq_placement = random.choice(_SEQ_PLACEMENTS)
    session_placement = random.choice(_SESSION_PLACEMENTS)

    def _name(placement: str) -> str:
        return random.choice(_HEADER_NAMES if placement == "header" else _QUERY_NAMES)

    low = random.randint(64, 256)
    return {
        # Добивка случайной длины: у запросов перестаёт быть характерный размер.
        "xPaddingBytes": f"{low}-{low + random.randint(400, 1200)}",
        "xPaddingKey": random.choice(_QUERY_NAMES + ["pad", "hash", "sig"]),
        "xPaddingHeader": random.choice(_HEADER_NAMES),
        "xPaddingMethod": "tokenish",
        "xPaddingPlacement": pad_placement,
        "xPaddingObfsMode": True,
        "seqKey": _name(seq_placement),
        "seqPlacement": seq_placement,
        "sessionIDKey": (
            random.choice(_HEADER_NAMES)
            if session_placement == "header"
            else random.choice(_TOKEN_NAMES)
        ),
        "sessionIDPlacement": session_placement,
        "sessionIDLength": random.choice([16, 20, 24, 32]),
    }


def has_obfuscation(settings: Dict[str, Any]) -> bool:
    """Есть ли у подключения маскировочные поля.

    Важно для подписки: обычная ссылка `vless://` такие параметры передать не
    умеет, клиент возьмёт настройки по умолчанию и не соединится. Поэтому
    подключение с маскировкой отдаётся только JSON-подпиской.
    """
    return any(settings.get(key) not in (None, "") for key in OBFUSCATION_KEYS)


def transport_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Блок xhttpSettings для конфига Xray — и сервера, и клиента."""
    block: Dict[str, Any] = {
        "path": settings.get("path", "/"),
        "mode": settings.get("mode", DEFAULT_MODE),
    }
    if settings.get("host"):
        block["host"] = settings["host"]
    for key in OBFUSCATION_KEYS:
        value = settings.get(key)
        if value not in (None, ""):
            block[key] = value
    if isinstance(settings.get("extra"), dict) and settings["extra"]:
        block["extra"] = settings["extra"]
    return block
