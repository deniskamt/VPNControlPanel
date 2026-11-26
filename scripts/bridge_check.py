#!/usr/bin/env python3
"""Почему мост не виден в подписке — и починить то, что можно.

    .venv/bin/python scripts/bridge_check.py          # только посмотреть
    .venv/bin/python scripts/bridge_check.py --fix    # и исправить

Исправляет то, что безопасно: возвращает мост в подписки, если он оттуда
убран, и выдаёт мостовое подключение пользователям, у которых его нет.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.database import session_scope  # noqa: E402
from app.models.enums import NodeAccessMode, UserStatus  # noqa: E402
from app.services import bridge, subscription_view  # noqa: E402
from app.services.node_manager import load_nodes, load_users  # noqa: E402
from app.services.users import grant_inbound_to_all  # noqa: E402


def say(ok: bool, text: str) -> None:
    print(("  [ок]   " if ok else "  [!!]   ") + text)


async def main(fix: bool) -> int:
    async with session_scope() as session:
        nodes = await load_nodes(session, only_enabled=False)
        bridges = [node for node in nodes if node.bridge]
        if not bridges:
            print("Мостов в панели нет.")
            print("Значит, сервер перестал быть мостом (нажали «Перестать быть мостом»)")
            print("или его удалили. Сделайте мост заново: Серверы → у российского сервера")
            print("«Ещё» → «Сделать мостом».")
            return 1

        users = await load_users(session)
        active = [u for u in users if u.status == UserStatus.active and not u.expired]
        problems = 0
        for node in bridges:
            print(f"\nМост «{node.name}» ({node.address})")
            say(node.is_enabled, "сервер включён" if node.is_enabled else
                "сервер ВЫКЛЮЧЕН — Серверы → «Ещё» → «Включить»")
            say(not node.probe_hidden, "в подписках" if not node.probe_hidden else
                "убран из подписок проверкой из России")
            say(node.access_mode == NodeAccessMode.all,
                "доступ: всем" if node.access_mode == NodeAccessMode.all else
                "доступ: ТОЛЬКО ВЫБРАННЫМ — Серверы → «Доступ» → «всем»")
            inbounds = [i for i in node.inbounds if i.tag == bridge.BRIDGE_TAG]
            say(bool(inbounds), "мостовое подключение на сервере есть" if inbounds else
                "на сервере НЕТ мостового подключения — сделайте его мостом заново")
            for inbound in inbounds:
                say(inbound.is_enabled, "мостовое подключение включено" if inbound.is_enabled else
                    "мостовое подключение ВЫКЛЮЧЕНО — Подключения → включить")
                missing = [u for u in active if inbound not in u.inbounds]
                say(not missing, f"подключение есть у всех активных пользователей ({len(active)})"
                    if not missing else
                    f"у {len(missing)} из {len(active)} пользователей мостового подключения нет")
                problems += bool(missing)
                if fix and missing:
                    granted = await grant_inbound_to_all(session, inbound)
                    print(f"         → выдано пользователям: {granted}")
            problems += (not node.is_enabled) + node.probe_hidden + (
                node.access_mode != NodeAccessMode.all) + (not inbounds)
            if fix and node.probe_hidden:
                node.probe_hidden = False
                print("         → возвращён в подписки")

            sample = active[0] if active else None
            if sample is not None:
                reasons = [r for r in subscription_view.hidden_entries(sample, nodes)
                           if node.name in r["what"]]
                for reason in reasons:
                    print(f"  У «{sample.username}» мост не в подписке: {reason['why']}")
        if fix:
            await session.commit()
            print("\nИсправлено. Обновите подписку в приложении.")
        elif problems:
            print("\nЗапустите с --fix, чтобы исправить то, что можно исправить автоматически.")
        else:
            print("\nВ панели с мостом всё в порядке — обновите подписку в приложении.")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fix", action="store_true")
    sys.exit(asyncio.run(main(parser.parse_args().fix)))
