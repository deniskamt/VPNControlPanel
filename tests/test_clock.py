"""Время не должно зависеть от часового пояса сервера.

datetime.utcnow().timestamp() трактует наивное время как местное: на сервере
с поясом Europe/Helsinki оно отставало на 2–3 часа. Подписки истекали
позже, сроки «на N дней» выходили короче, а после отзыва подписки новая
ссылка получала время выпуска раньше отзыва — и отвергалась как отозванная.
"""

import os
import time
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.core.clock import now_ts, to_ts


@pytest.fixture
def helsinki():
    before = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Helsinki"
    time.tzset()
    yield
    if before is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = before
    time.tzset()


def test_clock_ignores_server_timezone(helsinki):
    # Сам способ, которым панель считала время раньше, на этом поясе врёт.
    assert abs(int(datetime.utcnow().timestamp()) - int(time.time())) >= 3600

    assert abs(now_ts() - int(time.time())) <= 1
    assert abs(to_ts(datetime.utcnow()) - int(time.time())) <= 1


def test_new_link_after_revoke_is_not_revoked(helsinki):
    from app.services.subscription import get_subscription_payload
    from app.services.users import subscription_token

    revoked_at = datetime.utcnow().replace(microsecond=0)
    user = SimpleNamespace(username="u1", sub_revoked_at=revoked_at, created_at=revoked_at)

    payload = get_subscription_payload(subscription_token(user))

    # Ровно та проверка, что стоит в выдаче подписки.
    assert not payload["created_at"] < revoked_at.replace(microsecond=0)


def test_expired_flag_uses_real_time(helsinki):
    from app.models.user import User

    user = User(username="u2", expire=int(time.time()) - 60)
    assert user.expired
    user.expire = int(time.time()) + 60
    assert not user.expired
