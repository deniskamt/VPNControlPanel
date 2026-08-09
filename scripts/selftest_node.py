#!/usr/bin/env python3
"""Проверка подключения с самой ноды: поднимается ли туннель.

Скрипт берёт конфиг, который панель залила на сервер, собирает из него
клиента — ровно такого, каким его собрало бы приложение, — и пробует сходить
через него в интернет. Дальше вывод однозначный:

  * туннель работает с самой ноды  → сервер и настройки в порядке, значит
    дело в пути от пользователя до сервера (провайдер, ТСПУ, файрвол);
  * туннель не работает и здесь    → дело в сервере, и видно, на чём именно.

Запуск на VPN-сервере:  python3 selftest_node.py
Ничего не меняет, только читает конфиг и поднимает временного клиента.
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

XRAY = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
CONFIG = Path(os.getenv("XRAY_CONFIG", "/usr/local/etc/xray/config.json"))
TARGET = os.getenv("SELFTEST_URL", "https://www.gstatic.com/generate_204")


def say(mark: str, text: str) -> None:
    print(f"  [{mark}] {text}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def public_key(private: str) -> str:
    """Публичный ключ REALITY — в серверном конфиге его нет, выводим из приватного."""
    out = subprocess.run([XRAY, "x25519", "-i", private],
                         capture_output=True, text=True).stdout
    found = re.search(r"(?:Password \(PublicKey\)|Public ?[Kk]ey):\s*(\S+)", out)
    return found.group(1) if found else ""


def server_address() -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        result = subprocess.run(["curl", "-fsS", "--max-time", "10", url],
                                capture_output=True, text=True)
        address = result.stdout.strip()
        if result.returncode == 0 and address:
            return address
    return "127.0.0.1"


def client_config(inbound: Dict[str, Any], address: str, socks_port: int) -> Optional[Dict[str, Any]]:
    stream = inbound.get("streamSettings") or {}
    settings = inbound.get("settings") or {}
    clients = settings.get("clients") or []
    if not clients:
        return None

    account: Dict[str, Any] = {"id": clients[0]["id"], "encryption": "none"}
    if clients[0].get("flow"):
        account["flow"] = clients[0]["flow"]

    security = stream.get("security", "none")
    client_stream: Dict[str, Any] = {"network": stream.get("network", "tcp"),
                                     "security": security}

    if security == "reality":
        reality = stream.get("realitySettings") or {}
        pub = public_key(reality.get("privateKey", ""))
        if not pub:
            return None
        client_stream["realitySettings"] = {
            "serverName": (reality.get("serverNames") or [address])[0],
            "publicKey": pub,
            "shortId": (reality.get("shortIds") or [""])[0],
            "fingerprint": "firefox",
        }
    elif security == "tls":
        client_stream["tlsSettings"] = {
            "serverName": (stream.get("tlsSettings") or {}).get("serverName", address),
            "allowInsecure": True,
        }

    for key in ("xhttpSettings", "wsSettings", "grpcSettings", "httpupgradeSettings"):
        if stream.get(key):
            client_stream[key] = stream[key]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth"}}],
        "outbounds": [{"protocol": "vless",
                       "settings": {"vnext": [{"address": address,
                                               "port": inbound["port"],
                                               "users": [account]}]},
                       "streamSettings": client_stream}],
    }


def try_tunnel(inbound: Dict[str, Any], address: str, work: Path) -> Optional[str]:
    """Возвращает None при успехе, иначе причину."""
    socks_port = free_port()
    config = client_config(inbound, address, socks_port)
    if config is None:
        return "не удалось собрать клиента (нет пользователей или ключа)"

    path = work / "client.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    log = open(work / "client.log", "wb")
    process = subprocess.Popen([XRAY, "run", "-config", str(path)],
                               stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(2.5)
        if process.poll() is not None:
            tail = (work / "client.log").read_text(errors="replace").splitlines()
            reason = " ".join(line for line in tail if "Failed" in line)
            return f"клиент не запустился: {reason[:160] or 'см. лог'}"

        result = subprocess.run(
            ["curl", "-sS", "--max-time", "25", "-o", "/dev/null", "-w", "%{http_code}",
             "-x", f"socks5h://127.0.0.1:{socks_port}", TARGET],
            capture_output=True, text=True)
        code = result.stdout.strip()
        # Важен сам факт ответа, а не какой он. Любой HTTP-код значит, что
        # запрос дошёл до сайта и вернулся через туннель. «000» — это curl
        # не получил ничего: соединение не встало.
        if code and code != "000":
            return None
        return "через туннель не пришло ничего (соединение не встало)"
    finally:
        process.terminate()
        log.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", help="адрес сервера для проверки снаружи")
    args = parser.parse_args()

    if not Path(XRAY).exists():
        say("!!", f"нет ядра по пути {XRAY}")
        return 1
    if not CONFIG.exists():
        say("!!", f"нет конфига {CONFIG} — панель ещё ничего не залила")
        return 1
    if not shutil.which("curl"):
        say("!!", "нужен curl")
        return 1

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    inbounds: List[Dict[str, Any]] = [
        item for item in config.get("inbounds", [])
        if item.get("protocol") == "vless" and item.get("tag") != "api"
    ]

    print("== Может ли сервер дотянуться до маскировочного сайта ==")
    dests = {
        ((item.get("streamSettings") or {}).get("realitySettings") or {}).get("dest")
        for item in inbounds
    }
    for dest in sorted(filter(None, dests)):
        host = dest.split(":")[0]
        result = subprocess.run(
            ["curl", "-sS", "--max-time", "10", "-o", "/dev/null",
             "-w", "%{http_code}", f"https://{host}/"],
            capture_output=True, text=True)
        if result.stdout.strip().startswith(("2", "3", "4")):
            say("ok", f"{host} отвечает — REALITY есть у кого заимствовать рукопожатие")
        else:
            say("!!", f"{host} недоступен с сервера — REALITY работать не будет")
            say("!!", "смените маскировочный домен в панели на доступный отсюда")

    address = args.address or server_address()
    print()
    print(f"== Проверка подключений (внешний адрес {address}) ==")

    failures = 0
    with tempfile.TemporaryDirectory() as raw:
        work = Path(raw)
        for inbound in inbounds:
            tag = inbound.get("tag", "?")
            stream = inbound.get("streamSettings") or {}
            kind = f"{stream.get('network')}/{stream.get('security')}"
            port = inbound.get("port")

            local = try_tunnel(inbound, "127.0.0.1", work)
            if local is None:
                say("ok", f"{tag} ({kind}, порт {port}): туннель поднимается локально")
            else:
                say("!!", f"{tag} ({kind}, порт {port}): локально не работает — {local}")
                failures += 1
                continue

            outside = try_tunnel(inbound, address, work)
            if outside is None:
                say("ok", f"{tag}: работает и через внешний адрес")
            else:
                say("!!", f"{tag}: через внешний адрес не работает — {outside}")
                say("!!", "порт закрыт файрволом хостера или ядро слушает не тот адрес")
                failures += 1

    print()
    if failures:
        print("Итог: проблема на стороне сервера, смотрите строки [!!].")
    else:
        print("Итог: с самой ноды туннель работает — и локально, и по внешнему адресу.")
        print("Значит, сервер и настройки в порядке, а обрывается путь от")
        print("пользователя до сервера: провайдер, ТСПУ или файрвол по дороге.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
