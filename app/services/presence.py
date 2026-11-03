"""Кто сейчас на связи.

Метку `online_at` обновляет сбор трафика с нод: она означает «через этого
человека только что шёл трафик». Значит «в сети» — это не «приложение
открыто», а «прямо сейчас пользуется». Открытый, но простаивающий клиент
сюда не попадёт, и это честнее: панель показывает то, что действительно
видно по трафику.

Окно считаем от интервала опроса нод: если опрос раз в 30 секунд, метка
свежее полутора минут значит, что человек был на связи в последнем цикле.
Меньше брать нельзя — иначе точка будет гаснуть между опросами.
"""

from datetime import datetime, timedelta
from typing import Optional

from app.core.config import settings

# Не меньше двух минут: даже при частом опросе точка не должна мигать
# из-за одного пропущенного цикла.
MIN_WINDOW = timedelta(minutes=2)


def online_window() -> timedelta:
    """Насколько свежей должна быть метка, чтобы считать человека в сети."""
    return max(MIN_WINDOW, timedelta(seconds=settings.NODE_POLL_INTERVAL * 3))


def online_since() -> datetime:
    """Граница: всё, что новее, — в сети."""
    return datetime.utcnow() - online_window()


def is_online(moment: Optional[datetime]) -> bool:
    """В сети ли пользователь с такой меткой `online_at`."""
    return bool(moment and moment >= online_since())


def last_seen(moment: Optional[datetime]) -> str:
    """Человеческая подпись рядом с точкой."""
    if moment is None:
        return "не подключался"
    if is_online(moment):
        return "в сети"

    left = datetime.utcnow() - moment
    minutes = int(left.total_seconds() // 60)
    if minutes < 60:
        return f"{max(1, minutes)} мин назад"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} ч назад"
    days = hours // 24
    if days < 30:
        return f"{days} дн назад"
    return moment.strftime("%d.%m.%Y")


# Сколько времени назад ещё показывать человека в списке сервера: «сейчас»
# мало что говорит, если он отключился минуту назад, а сутки — разумный
# горизонт для вопроса «кто вообще сидит на этом сервере».
RECENT_WINDOW = timedelta(hours=24)


async def users_by_node(session) -> dict:
    """Кто на каком сервере: {номер сервера: [строка, …]}, сначала те, кто в сети.

    Строка — {"user", "online_at", "online", "used_traffic"}. Считается по
    трафику: сервер, через который у человека последним шли данные, и есть
    тот, на котором он сидит. Один человек может быть сразу на нескольких
    серверах — например, телефон на одном, ноутбук на другом.
    """
    from sqlalchemy import select

    from app.models.access import UserNodeAccess
    from app.models.user import User

    since = datetime.utcnow() - RECENT_WINDOW
    result = await session.execute(
        select(UserNodeAccess, User)
        .join(User, User.id == UserNodeAccess.user_id)
        .where(UserNodeAccess.online_at >= since)
    )
    grouped: dict = {}
    for access, user in result.all():
        grouped.setdefault(access.node_id, []).append(
            {
                "user": user,
                "online_at": access.online_at,
                "online": is_online(access.online_at),
                "used_traffic": access.used_traffic,
            }
        )
    for rows in grouped.values():
        rows.sort(key=lambda row: (not row["online"], -row["online_at"].timestamp(), row["user"].username))
    return grouped
