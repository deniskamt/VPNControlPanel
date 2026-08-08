"""Код агента, который панель раздаёт и рассылает на ноды.

Единственный источник правды о версии — сам файл agent/agent.py: панель
читает из него константу AGENT_VERSION и сравнивает с тем, что сообщает нода
в /health. Так после `git pull` сразу видно, где агент отстал.
"""

import re
from pathlib import Path
from typing import Optional

AGENT_PATH = Path(__file__).resolve().parents[2] / "agent" / "agent.py"

_VERSION_RE = re.compile(r"^AGENT_VERSION\s*=\s*(\d+)", re.MULTILINE)


def read_source() -> str:
    return AGENT_PATH.read_text(encoding="utf-8")


def bundled_version(source: Optional[str] = None) -> int:
    """Версия агента, лежащего в этой копии панели."""
    match = _VERSION_RE.search(source if source is not None else read_source())
    return int(match.group(1)) if match else 0


def is_outdated(node_version: Optional[int], bundled: Optional[int] = None) -> bool:
    """Нужно ли обновлять агента на ноде.

    Агенты до появления версии её не сообщают: None — это «древний», а не
    «неизвестно, лучше промолчать».
    """
    expected = bundled if bundled is not None else bundled_version()
    return (node_version or 0) < expected
