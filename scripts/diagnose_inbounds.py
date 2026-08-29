#!/usr/bin/env python3
"""Почему подключение не работает: одна таблица вместо десяти команд.

Отвечает на три вопроса разом, по каждой паре «сервер + подключение»:

  * есть ли оно в базе и на этом ли сервере оно включено;
  * доехал ли конфиг до ноды — по её состоянию и последней ошибке;
  * открыт ли порт снаружи — панель сама стучится в него.

Этого хватает, чтобы отличить три совершенно разные беды, которые снаружи
выглядят одинаково («не подключается»): подключение не раскатано, конфиг не
доехал, порт закрыт файрволом.

    cd /opt/vpn-panel && .venv/bin/python scripts/diagnose_inbounds.py
"""

from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.core.database import SessionLocal  # noqa: E402
from app.models.enums import ProxyType  # noqa: E402
from app.models.inbound import Inbound  # noqa: E402
from app.models.node import Node  # noqa: E402
from app.services import hysteria  # noqa: E402

TIMEOUT = 5.0


def check_tcp(address: str, port: int) -> str:
    """Стучимся в порт так же, как это сделал бы клиент."""
    try:
        with socket.create_connection((address, port), timeout=TIMEOUT):
            return "открыт"
    except socket.timeout:
        return "таймаут"
    except ConnectionRefusedError:
        return "закрыт"
    except OSError as exc:
        return f"ошибка: {exc.strerror or exc}"


def check_udp(address: str, port: int) -> str:
    """UDP молчит по своей природе — проверить можно только маршрут.

    Ответа тут не бывает, поэтому честно говорим, что не знаем.
    """
    return "не проверить (UDP)"


async def main() -> None:
    async with SessionLocal() as session:
        nodes = list(
            (await session.execute(select(Node).order_by(Node.id))).scalars().all()
        )
        inbounds = list(
            (await session.execute(select(Inbound).order_by(Inbound.id))).scalars().all()
        )

    if not inbounds:
        print("В панели нет ни одного подключения — создавать нечего.")
        return

    print("\nПОДКЛЮЧЕНИЯ")
    print(f"{'тег':<24} {'порт':>6}  {'вкл':<4} {'серверов':>8}")
    for inbound in inbounds:
        print(
            f"{inbound.tag[:24]:<24} {inbound.port:>6}  "
            f"{'да' if inbound.is_enabled else 'НЕТ':<4} {len(inbound.nodes):>8}"
        )
        if not inbound.nodes:
            print("     ↑ ни на одном сервере — ссылки выдаются, слушать некому")

    print("\nСЕРВЕРЫ")
    for node in nodes:
        state = node.status.value if node.status else "?"
        print(f"\n  {node.name} ({node.address})  состояние: {state}")
        if node.message:
            print(f"    последняя ошибка: {node.message[:300]}")
        if not node.is_enabled:
            print("    сервер выключен в панели")
            continue

        applicable = [item for item in node.inbounds if item.is_enabled]
        if not applicable:
            print("    подключений на нём нет")
            continue

        for inbound in sorted(applicable, key=lambda item: item.id):
            if inbound.protocol == ProxyType.hysteria2:
                result = check_udp(node.address, inbound.port)
            else:
                result = check_tcp(node.address, inbound.port)
            print(f"    {inbound.tag[:24]:<24} порт {inbound.port:>5}: {result}")

    print(
        "\nКАК ЧИТАТЬ\n"
        "  «закрыт»  — на ноде никто не слушает: конфиг не доехал или Xray его\n"
        "              не принял. Смотрите последнюю ошибку сервера выше.\n"
        "  «таймаут» — порт есть, но его режет файрвол: у хостера или ufw.\n"
        "  «открыт»  — сервер работает. Если клиент всё равно не подключается,\n"
        "              дело в параметрах: версия ядра, отпечаток, маскировочный\n"
        "              домен, время на сервере (timedatectl).\n"
    )


if __name__ == "__main__":
    asyncio.run(main())
