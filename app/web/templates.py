"""Jinja-окружение веб-панели."""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.services.flags import country_code, country_flag

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Какие флаги лежат картинками. Список снимаем один раз при запуске:
# на каждую строку таблицы ходить в файловую систему незачем.
FLAG_DIR = BASE_DIR / "static" / "flags"
FLAG_FILES = {path.stem.upper() for path in FLAG_DIR.glob("*.svg")}


def flag(country: Optional[str]) -> Markup:
    """Флаг страны картинкой.

    Эмодзи-флаг рисуется только тем шрифтом, где он есть: в Windows и в
    части браузеров вместо флага показываются две буквы. Поэтому в панели
    отдаём svg, а эмодзи оставляем запасным вариантом — для стран, которых
    нет в наборе.
    """
    code = country_code(country)
    if code in FLAG_FILES:
        return Markup(
            f'<img class="flag" src="/static/flags/{code.lower()}.svg" '
            f'alt="{code}" width="20" height="15" loading="lazy">'
        )
    return Markup(escape(country_flag(country)))


# Пара букв-индикаторов — это и есть эмодзи флага.
_FLAG_PAIR = re.compile("[\U0001f1e6-\U0001f1ff]{2}")


def flag_text(value: Optional[str]) -> Markup:
    """Название конфигурации, где эмодзи-флаг заменён картинкой.

    В названии, которое уедет клиенту, флаг обязан остаться эмодзи —
    приложения рисуют иконку страны только по нему. А на странице показываем
    ровно то, что увидит человек в приложении, только флаг настоящий.
    """
    text = str(value or "")
    parts = []
    last = 0
    for match in _FLAG_PAIR.finditer(text):
        parts.append(escape(text[last : match.start()]))
        parts.append(flag(match.group()))
        last = match.end()
    parts.append(escape(text[last:]))
    return Markup("").join(parts)


def asset(path: str) -> str:
    """Адрес файла статики с меткой версии.

    Браузер держит css и js в кеше, и после обновления панели человек видит
    старое оформление — пока не нажмёт Ctrl+F5. Метка — время правки файла:
    меняется вместе с файлом и ничего не требует от нас.
    """
    name = path.lstrip("/")
    try:
        stamp = int((BASE_DIR / "static" / name).stat().st_mtime)
    except OSError:
        return f"/static/{name}"
    return f"/static/{name}?v={stamp}"


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
# Флаг страны нужен в нескольких шаблонах — от списка серверов до подписки.
templates.env.globals["flag"] = flag
templates.env.filters["flags"] = flag_text
templates.env.globals["asset"] = asset
templates.env.globals["now"] = datetime.utcnow
