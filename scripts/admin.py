#!/usr/bin/env python3
"""Администраторы панели: посмотреть список, сбросить пароль, добавить нового.

    python scripts/admin.py list
    python scripts/admin.py set-password --username admin
    python scripts/admin.py set-password --username admin --password 'мой пароль'

Пароль в базе, а не в .env: переменная ADMIN_PASSWORD срабатывает только при
самом первом запуске, когда админов ещё нет. Дальше пароль меняется отсюда.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.core.database import SessionLocal, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models import Admin, Base  # noqa: E402


async def _ensure_tables() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def list_admins() -> int:
    await _ensure_tables()
    async with SessionLocal() as session:
        admins = list((await session.execute(select(Admin).order_by(Admin.id))).scalars())

    if not admins:
        print("Администраторов нет — первый создастся при запуске панели "
              "из ADMIN_USERNAME/ADMIN_PASSWORD в .env")
        return 0

    for admin in admins:
        flags = []
        if admin.is_sudo:
            flags.append("sudo")
        if not admin.is_active:
            flags.append("отключён")
        suffix = f" ({', '.join(flags)})" if flags else ""
        last = admin.last_login_at.strftime("%d.%m.%Y %H:%M") if admin.last_login_at else "—"
        print(f"{admin.username}{suffix}, последний вход: {last}")
    return len(admins)


async def set_password(username: str, password: str | None) -> None:
    await _ensure_tables()
    password = password or secrets.token_urlsafe(12)

    async with SessionLocal() as session:
        admin = (
            await session.execute(select(Admin).where(Admin.username == username))
        ).scalar_one_or_none()

        if admin is None:
            admin = Admin(
                username=username,
                hashed_password=hash_password(password),
                is_sudo=True,
                created_at=datetime.utcnow(),
            )
            session.add(admin)
            action = "создан"
        else:
            admin.hashed_password = hash_password(password)
            admin.is_active = True
            action = "обновлён"

        await session.commit()

    print(f"Администратор «{username}» {action}.")
    print(f"Пароль: {password}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Администраторы панели")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list", help="показать администраторов")

    setter = commands.add_parser(
        "set-password", help="задать пароль (админ создаётся, если его нет)"
    )
    setter.add_argument("--username", default="admin")
    setter.add_argument(
        "--password", default=None, help="если не указан — сгенерируется случайный"
    )

    args = parser.parse_args()

    if args.command == "list":
        asyncio.run(list_admins())
    else:
        asyncio.run(set_password(args.username, args.password))


if __name__ == "__main__":
    main()
