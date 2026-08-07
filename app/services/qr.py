"""QR-коды для ссылок подписки.

Нужны, чтобы подписку можно было забрать телефоном, не пересылая ссылку.
Картинка встраивается в страницу как SVG — без обращений наружу.
"""

from typing import Optional

import segno
from loguru import logger


def qr_svg(data: str, scale: int = 4) -> Optional[str]:
    """Инлайновый SVG или None, если данные слишком длинные для QR."""
    if not data:
        return None
    try:
        code = segno.make(data, error="m")
        return code.svg_inline(scale=scale, dark="#0f1117", light="#ffffff")
    except Exception as exc:  # noqa: BLE001 — QR не должен ронять страницу
        logger.warning(f"Не удалось построить QR: {exc}")
        return None
