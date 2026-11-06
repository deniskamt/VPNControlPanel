"""Какая версия ядра Xray нужна на серверах.

Разработчик Xray про ТСПУ осенью 2026: оно «больше похоже на погоню за
значениями Xray по умолчанию» — свежее ядро несёт свежие отпечатки uTLS и
исправления REALITY. 26.10.21 — версия, которую рекомендуют отчёты осени 2026
(обновление безопасности). На ней проверено вручную: конфиг XHTTP+REALITY,
который собирает панель, принимается и пропускает трафик, а агент 6
обновляется до неё с проверкой и откатом.
"""

import re
from typing import Optional, Tuple

RECOMMENDED = "v26.10.21"


def parse(version: Optional[str]) -> Optional[Tuple[int, ...]]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(part) for part in match.groups()) if match else None


def is_outdated(version: Optional[str], recommended: str = RECOMMENDED) -> bool:
    """Старее рекомендуемого. Неизвестную версию старой не считаем: о ней молчим."""
    current = parse(version)
    return current is not None and current < parse(recommended)
