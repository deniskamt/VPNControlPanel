"""Время в секундах Unix — одинаково на сервере с любым часовым поясом.

Панель хранит время в базе «наивным» UTC (datetime.utcnow()). Метод
.timestamp() у наивного datetime считает его МЕСТНЫМ временем: на сервере
с поясом Europe/Helsinki datetime.utcnow().timestamp() отстаёт от настоящего
времени на 2–3 часа. Из-за этого подписки истекали на пару часов позже,
сроки «на N дней» выходили на пару часов короче, а после отзыва подписки
новая ссылка получала время выпуска раньше момента отзыва — и панель сама
же отвергала её как отозванную.
"""

import time
from datetime import datetime, timezone


def now_ts() -> int:
    """Текущий момент, секунды Unix."""
    return int(time.time())


def to_ts(moment: datetime) -> int:
    """Момент из базы (наивный UTC) — в секунды Unix, без поправки на пояс."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())
