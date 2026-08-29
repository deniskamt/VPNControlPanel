#!/usr/bin/env python3
"""Подбор маскировочного домена для REALITY — с самой ноды.

Зачем. REALITY выдаёт себя за настоящий сайт: клиент говорит «я иду на
www.example.com», а сервер при каждом рукопожатии ходит к нему по-настоящему.
Домен из гайда для этого не годится по трём причинам:

  * он у всех одинаковый, и это само по себе примета;
  * он может не поддерживать TLS 1.3 или HTTP/2 — тогда рукопожатие
    рассыпается и подключение просто не работает;
  * он может быть далеко от ноды — каждое рукопожатие ждёт ответа, и
    задержка достаётся пользователю.

Скрипт проверяет кандидатов ровно так, как их будет использовать REALITY,
и печатает те, что годятся, отсортированные по задержке.

    python3 scripts/pick_dest.py                       # список по умолчанию
    python3 scripts/pick_dest.py bing.com yandex.ru    # свои кандидаты

Запускать на ноде: важна задержка именно от неё.
"""

from __future__ import annotations

import socket
import ssl
import sys
import time
from typing import List, Optional, Tuple

# Кандидаты «по умолчанию» намеренно не из популярных гайдов: домены оттуда
# примелькались. Это крупные сайты с современным TLS, чьё присутствие в
# трафике никого не удивляет.
CANDIDATES = [
    "www.samsung.com",
    "www.lg.com",
    "www.asus.com",
    "www.sony.com",
    "www.philips.com",
    "www.bosch.com",
    "www.siemens.com",
    "www.canon.com",
    "www.nikon.com",
    "www.tp-link.com",
]

TIMEOUT = 6.0


def probe(domain: str) -> Tuple[bool, str, Optional[float]]:
    """Проверить домен так, как это сделает REALITY.

    Возвращает (годится, пояснение, задержка в мс).
    """
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    started = time.monotonic()
    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                delay = (time.monotonic() - started) * 1000
                version = tls.version()
                alpn = tls.selected_alpn_protocol()
                names = certificate_names(tls.getpeercert())
    except ssl.SSLError as exc:
        return False, f"TLS не сложился: {exc.reason or exc}", None
    except socket.timeout:
        return False, "таймаут", None
    except OSError as exc:
        return False, f"не доступен: {exc.strerror or exc}", None

    if version != "TLSv1.3":
        return False, f"только {version}, а REALITY нужен TLS 1.3", delay
    if alpn != "h2":
        return False, "нет HTTP/2 — рукопожатие будет выглядеть иначе", delay
    if not covers(domain, names):
        return False, f"сертификат выписан не на него: {', '.join(names[:3])}", delay

    return True, "годится", delay


def certificate_names(cert: Optional[dict]) -> List[str]:
    """Имена, на которые выписан сертификат."""
    if not cert:
        return []
    names = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]
    for field in cert.get("subject", ()):
        for key, value in field:
            if key == "commonName" and value not in names:
                names.append(value)
    return names


def covers(domain: str, names: List[str]) -> bool:
    """Покрывает ли сертификат этот домен — вместе с масками вида *.a.b."""
    for name in names:
        if name == domain:
            return True
        if name.startswith("*.") and domain.endswith(name[1:]):
            return True
    return False


def main() -> None:
    domains = sys.argv[1:] or CANDIDATES
    годные: List[Tuple[float, str]] = []

    print(f"\nПроверяю {len(domains)} доменов так же, как это делает REALITY\n")
    for domain in domains:
        ok, note, delay = probe(domain)
        задержка = f"{delay:5.0f} мс" if delay else "   —   "
        значок = "✓" if ok else "✗"
        print(f"  {значок} {domain:<28} {задержка}  {note}")
        if ok and delay is not None:
            годные.append((delay, domain))

    if not годные:
        print(
            "\nНи один не подошёл. Проверьте, что с ноды вообще есть выход "
            "наружу по 443, и попробуйте свои варианты:\n"
            "  python3 scripts/pick_dest.py site1.com site2.com\n"
        )
        return

    годные.sort()
    print("\nЛучшие — по задержке от этой ноды:")
    for delay, domain in годные[:3]:
        print(f"  {domain}  ({delay:.0f} мс)")

    print(
        "\nЧто с ними делать: в панели у подключения «Настроить» → параметры\n"
        f'  "dest": "{годные[0][1]}:443",\n'
        f'  "serverNames": ["{годные[0][1]}"]\n'
        "Разным нодам давайте разные домены: одинаковые настройки на всех — \n"
        "это одна примета на весь ваш сервис, и блокируется она разом.\n"
    )


if __name__ == "__main__":
    main()
