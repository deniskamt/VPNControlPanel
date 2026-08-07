"""Jinja-окружение веб-панели."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def human_bytes(value: Optional[int]) -> str:
    if not value:
        return "0 B"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024 or unit == "PB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def human_datetime(value: Optional[datetime]) -> str:
    return value.strftime("%d.%m.%Y %H:%M") if value else "—"


def human_expire(value: Optional[int]) -> str:
    if not value:
        return "бессрочно"
    moment = datetime.utcfromtimestamp(value)
    left = moment - datetime.utcnow()
    if left.total_seconds() <= 0:
        return f"истекла {moment.strftime('%d.%m.%Y')}"
    days = left.days
    if days >= 1:
        return f"{moment.strftime('%d.%m.%Y')} ({days} дн.)"
    return f"{moment.strftime('%d.%m.%Y %H:%M')} (<1 дн.)"


def human_uptime(value: Optional[int]) -> str:
    if not value:
        return "—"
    days, rest = divmod(int(value), 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}д {hours}ч"
    if hours:
        return f"{hours}ч {minutes}м"
    return f"{minutes}м"


def usage_percent(used: Optional[int], limit: Optional[int]) -> int:
    if not limit:
        return 0
    return min(100, int((used or 0) / limit * 100))


templates.env.filters["bytes"] = human_bytes
templates.env.filters["dt"] = human_datetime
templates.env.filters["expire"] = human_expire
templates.env.filters["uptime"] = human_uptime
templates.env.globals["usage_percent"] = usage_percent
templates.env.globals["now"] = datetime.utcnow
