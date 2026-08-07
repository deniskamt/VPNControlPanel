#!/usr/bin/env python3
"""Серверы панели из командной строки: список, токены, команда установки.

Пригодится, когда до веб-панели не добраться или хочется скопировать команду
установки агента прямо на сервере.

    python scripts/node.py list          # серверы и их состояние
    python scripts/node.py install       # команда установки для каждого
    python scripts/node.py install --name "Sweden - Stockholm"
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.database import SessionLocal, engine  # noqa: E402
from app.models import Base, Node  # noqa: E402


async def _nodes(name: str | None = None):
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with SessionLocal() as session:
        query = select(Node).order_by(Node.sort_order, Node.id)
        if name:
            query = query.where(Node.name == name)
        return list((await session.execute(query)).scalars().all())


async def list_nodes() -> None:
    nodes = await _nodes()
    if not nodes:
        print("Серверов пока нет — добавьте на странице «Серверы».")
        return

    for node in nodes:
        state = node.status.value if node.is_enabled else "выключен"
        print(f"{node.name} — {node.address}, агент {node.agent_base_url}, {state}")
        if node.message:
            print(f"    {node.message}")


async def install_command(name: str | None) -> None:
    nodes = await _nodes(name)
    if not nodes:
        print("Сервер не найден." if name else "Серверов пока нет.")
        return

    panel = settings.PANEL_URL
    for node in nodes:
        print(f"\n# {node.name} ({node.address}) — выполнить на этом сервере под root:")
        print(f"curl -fsSL {panel}/install/install_agent.sh -o install_agent.sh")
        print(
            f"AGENT_TOKEN={node.agent_token} PANEL_URL={panel} bash install_agent.sh"
        )

    print(
        "\n# Скрипт поставит Xray и агента и поднимет сервис vpn-agent."
        "\n# Если панель и сервер — одна машина, в поле «Адрес агента»"
        "\n# в панели укажите 127.0.0.1, тогда порт наружу открывать не нужно."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Серверы панели")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="показать серверы")
    installer = commands.add_parser("install", help="команда установки агента")
    installer.add_argument("--name", default=None, help="только для этого сервера")

    args = parser.parse_args()
    if args.command == "list":
        asyncio.run(list_nodes())
    else:
        asyncio.run(install_command(args.name))


if __name__ == "__main__":
    main()
