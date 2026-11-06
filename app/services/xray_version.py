"""Какая версия ядра Xray должна стоять на серверах.

Не «самая свежая», а самая совместимая. Ядро сервера решает, какие клиенты
смогут подключиться, а в приложениях у людей ядро бывает очень старым:
у flutter_v2ray, на котором построен AppVPN, — 25.3.6.

Проверено на стенде (VISION и XHTTP под REALITY, отпечатки firefox и chrome,
по 10 запросов на клетку):

  сервер \\ клиент   25.3.6   25.10.15            26.3.27   26.10.21
  25.3.6            да
  25.10.15          да       да                            да
  26.3.27           да       да                   да        да
  26.7.28           НЕТ      НЕТ                  да        да
  26.9.30           НЕТ      только chrome        да        да
  26.10.21          НЕТ      только chrome        да        да

Начиная с 26.7 сервер перестаёт пускать клиентов на ядре 25.x — при любом
отпечатке. Поэтому на серверах держим 26.3.27: она пускает и старых, и новых.
Обновление до 26.10.21, которое панель предлагала раньше по отчётам осени
2026, отрезало всех клиентов на старом ядре — его надо откатить.
"""

import re
from typing import Optional, Tuple

RECOMMENDED = "v26.3.27"


def parse(version: Optional[str]) -> Optional[Tuple[int, ...]]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(part) for part in match.groups()) if match else None


def differs(version: Optional[str], recommended: str = RECOMMENDED) -> bool:
    """Ядро не той версии — старее или новее. Неизвестную не трогаем."""
    current = parse(version)
    return current is not None and current != parse(recommended)


def too_new(version: Optional[str], recommended: str = RECOMMENDED) -> bool:
    """Новее выбранной: такое ядро может не пускать клиентов на старом ядре."""
    current = parse(version)
    return current is not None and current > parse(recommended)


def is_outdated(version: Optional[str], recommended: str = RECOMMENDED) -> bool:
    current = parse(version)
    return current is not None and current < parse(recommended)
