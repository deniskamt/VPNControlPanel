#!/usr/bin/env python3
"""Перенос базы Marzban в панель.

Главное, ради чего скрипт нужен: у пользователей остаются те же ссылки
подписок и те же UUID/пароли, поэтому переход происходит незаметно —
переустанавливать конфиги в приложениях не требуется.

Что переносится:
  * секрет подписи подписок из таблицы `jwt` (его нужно положить в
    SUBSCRIPTION_SECRET — без него старые ссылки перестанут открываться);
  * администраторы вместе с bcrypt-хешами паролей;
  * пользователи: статус, трафик, лимит, срок, заметки, даты;
  * ключи пользователей (uuid vless/vmess, пароли trojan/shadowsocks);
  * хосты для ссылок;
  * ноды (в выключенном состоянии — на них ещё нужно поставить наш агент);
  * inbound'ы: теги из БД, а полные параметры — из xray_config.json,
    если указать путь через --xray-config.

Использование:

    pip install -r requirements.txt -r requirements-migrate.txt

    python scripts/migrate_from_marzban.py \\
        --source "mysql+pymysql://marzban:pass@127.0.0.1:3306/marzban" \\
        --xray-config /var/lib/marzban/xray_config.json \\
        --dry-run

Для SQLite-установки Marzban:

    --source "sqlite:////var/lib/marzban/db.sqlite3"

Скрипт идемпотентен: существующие в панели записи пропускаются, поэтому
его можно запустить повторно (например, ещё раз перед самым переключением
DNS, чтобы догнать свежие данные).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import MetaData, Table, create_engine, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.services.keys import public_key_from_private  # noqa: E402
from app.services.presets import MIN_CLIENT_VERSION  # noqa: E402
from app.models import (  # noqa: E402
    Admin,
    Base,
    DataLimitResetStrategy,
    Host,
    Inbound,
    NetworkType,
    Node,
    NodeStatus,
    ProxyType,
    SecurityType,
    User,
    UserProxy,
    UserStatus,
)

# --- Разбор xray_config.json Marzban ---------------------------------------

_NETWORK_MAP = {
    "tcp": NetworkType.tcp,
    "raw": NetworkType.tcp,
    "ws": NetworkType.ws,
    "websocket": NetworkType.ws,
    "grpc": NetworkType.grpc,
    "httpupgrade": NetworkType.httpupgrade,
    "xhttp": NetworkType.xhttp,
    "splithttp": NetworkType.xhttp,
}


def _inbound_from_xray(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Превращает inbound из конфига Marzban в параметры нашей модели."""
    protocol = (raw.get("protocol") or "").lower()
    if protocol not in {item.value for item in ProxyType}:
        return None  # api/dokodemo-door и прочее служебное пропускаем

    stream = raw.get("streamSettings") or {}
    network_raw = (stream.get("network") or "tcp").lower()
    security_raw = (stream.get("security") or "none").lower()

    options: Dict[str, Any] = {}

    ws = stream.get("wsSettings") or {}
    if ws:
        options["path"] = ws.get("path", "/")
        options["host"] = (ws.get("headers") or {}).get("Host", "")

    grpc = stream.get("grpcSettings") or {}
    if grpc:
        options["serviceName"] = grpc.get("serviceName", "")
        if grpc.get("multiMode"):
            options["multiMode"] = True

    upgrade = stream.get("httpupgradeSettings") or stream.get("xhttpSettings") or {}
    if upgrade:
        options["path"] = upgrade.get("path", "/")
        options["host"] = upgrade.get("host", "")
        if upgrade.get("mode"):
            options["mode"] = upgrade["mode"]

    tcp = stream.get("tcpSettings") or stream.get("rawSettings") or {}
    header = (tcp.get("header") or {}).get("type")
    if header == "http":
        options["header_type"] = "http"
        request = (tcp.get("header") or {}).get("request") or {}
        paths = request.get("path") or ["/"]
        options["path"] = paths[0]
        hosts = (request.get("headers") or {}).get("Host") or [""]
        options["host"] = hosts[0]

    tls = stream.get("tlsSettings") or {}
    if tls:
        options["sni"] = tls.get("serverName", "")
        if tls.get("alpn"):
            options["alpn"] = ",".join(tls["alpn"])
        certificates = tls.get("certificates") or []
        if certificates:
            options["certificateFile"] = certificates[0].get("certificateFile", "")
            options["keyFile"] = certificates[0].get("keyFile", "")

    reality = stream.get("realitySettings") or {}
    if reality:
        options["dest"] = reality.get("dest", "")
        options["serverNames"] = reality.get("serverNames") or []
        options["privateKey"] = reality.get("privateKey", "")
        options["shortIds"] = reality.get("shortIds") or [""]
        options["xver"] = reality.get("xver", 0)
        # publicKey в серверном конфиге Xray не хранится — он нужен только
        # клиенту. Раньше его приходилось получать на сервере командой
        # `xray x25519 -i` и вписывать руками для каждого подключения; теперь
        # он считается из приватного прямо здесь.
        options["publicKey"] = public_key_from_private(options["privateKey"])
        # Свежие ядра иначе пускают только клиентов не старше себя.
        options.setdefault("minClientVer", MIN_CLIENT_VERSION)

    clients = (raw.get("settings") or {}).get("clients") or []
    if clients:
        if clients[0].get("flow"):
            options["flow"] = clients[0]["flow"]
        if clients[0].get("method"):
            options["method"] = clients[0]["method"]

    return {
        "tag": raw.get("tag") or f"{protocol}-{raw.get('port')}",
        "protocol": ProxyType(protocol),
        "port": int(raw.get("port") or 0),
        "listen": raw.get("listen") or "0.0.0.0",
        "network": _NETWORK_MAP.get(network_raw, NetworkType.tcp),
        "security": SecurityType(security_raw)
        if security_raw in {item.value for item in SecurityType}
        else SecurityType.none,
        "settings": options,
    }


def load_xray_inbounds(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    if not path:
        return {}
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    result: Dict[str, Dict[str, Any]] = {}
    for raw in config.get("inbounds") or []:
        parsed = _inbound_from_xray(raw)
        if parsed:
            result[parsed["tag"]] = parsed
    return result


# --- Чтение исходной базы --------------------------------------------------


class MarzbanSource:
    """Тонкая обёртка над базой Marzban через рефлексию схемы.

    Рефлексия, а не модели: у разных версий Marzban набор колонок отличается,
    и жёсткая схема сломалась бы на первой же нестандартной установке.
    """

    def __init__(self, url: str) -> None:
        self.engine = create_engine(url)
        self.metadata = MetaData()

    def table(self, name: str) -> Optional[Table]:
        try:
            return Table(name, self.metadata, autoload_with=self.engine)
        except Exception:
            return None

    def rows(self, name: str) -> List[Dict[str, Any]]:
        table = self.table(name)
        if table is None:
            print(f"  · таблицы {name} нет — пропускаем")
            return []
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(select(table)).mappings()]


# --- Перенос ---------------------------------------------------------------


def _as_datetime(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _enum_value(value: Any, default: str) -> str:
    if value is None:
        return default
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def write_secret_to_env(env_path: Path, secret: str) -> None:
    """Прописать SUBSCRIPTION_SECRET в .env, не трогая остальные строки.

    Без совпадающего секрета ссылки, выданные Marzban, не открываются, а
    редактировать .env руками на свежем сервере бывает нечем — там может не
    оказаться даже nano.
    """
    if not secret:
        print("  Секрет пуст — записывать нечего.")
        return
    if not env_path.exists():
        print(f"  Нет файла {env_path} — впишите секрет вручную.")
        return

    lines = env_path.read_text(encoding="utf-8").splitlines()
    replaced = False
    for index, line in enumerate(lines):
        if line.startswith("SUBSCRIPTION_SECRET="):
            if line.strip() == f"SUBSCRIPTION_SECRET={secret}":
                print(f"  В {env_path} секрет уже такой — ничего не меняем.")
                return
            lines[index] = f"SUBSCRIPTION_SECRET={secret}"
            replaced = True
            break
    if not replaced:
        lines.append(f"SUBSCRIPTION_SECRET={secret}")

    backup = env_path.with_suffix(env_path.suffix + ".bak")
    backup.write_text(env_path.read_text(encoding="utf-8"), encoding="utf-8")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Секрет записан в {env_path} (копия прежнего — {backup}).")
    print("  Перезапустите панель: systemctl restart vpn-panel")


def migrate(
    source: MarzbanSource,
    session: Session,
    xray_inbounds: Dict[str, Dict[str, Any]],
    dry_run: bool,
    limit: Optional[int] = None,
    env_path: Optional[Path] = None,
) -> None:
    report: Dict[str, int] = {}

    # 1. Секрет подписи подписок ------------------------------------------
    print("\n[1/6] Секрет подписи подписок")
    jwt_rows = source.rows("jwt")
    if jwt_rows:
        secret = jwt_rows[0].get("secret_key", "")
        print("  Найден секрет Marzban. Пропишите его в .env панели:\n")
        print(f"    SUBSCRIPTION_SECRET={secret}\n")
        if env_path and not dry_run:
            write_secret_to_env(env_path, secret)
        if settings.SUBSCRIPTION_SECRET and settings.SUBSCRIPTION_SECRET != secret:
            print(
                "  ВНИМАНИЕ: в .env панели указан ДРУГОЙ секрет — старые ссылки "
                "работать не будут, пока значения не совпадут."
            )
    else:
        print("  Секрет не найден: старые ссылки проверить будет нечем.")

    # 2. Администраторы -----------------------------------------------------
    print("\n[2/6] Администраторы")
    created = 0
    for row in source.rows("admins"):
        username = row.get("username")
        if not username:
            continue
        exists = session.scalar(select(Admin).where(Admin.username == username))
        if exists:
            continue
        session.add(
            Admin(
                username=username,
                hashed_password=row.get("hashed_password") or "",
                is_sudo=bool(row.get("is_sudo")),
                telegram_id=row.get("telegram_id"),
                created_at=_as_datetime(row.get("created_at")) or datetime.utcnow(),
            )
        )
        created += 1
    report["admins"] = created
    print(f"  перенесено: {created}")

    # 3. Inbound'ы ----------------------------------------------------------
    print("\n[3/6] Подключения (inbound)")
    tags = [row.get("tag") for row in source.rows("inbounds") if row.get("tag")]
    for tag in xray_inbounds:
        if tag not in tags:
            tags.append(tag)

    created = 0
    inbound_by_tag: Dict[str, Inbound] = {}
    for tag in tags:
        existing = session.scalar(select(Inbound).where(Inbound.tag == tag))
        if existing:
            inbound_by_tag[tag] = existing
            continue

        parsed = xray_inbounds.get(tag)
        if parsed:
            inbound = Inbound(
                tag=tag,
                protocol=parsed["protocol"],
                port=parsed["port"],
                listen=parsed["listen"],
                network=parsed["network"],
                security=parsed["security"],
                settings=parsed["settings"],
            )
        else:
            # Без xray_config.json известен только тег: создаём заготовку,
            # порт и параметры админ дозаполнит в панели.
            inbound = Inbound(
                tag=tag,
                protocol=ProxyType.vless,
                port=0,
                network=NetworkType.tcp,
                security=SecurityType.none,
                settings={},
                is_enabled=False,
            )
        session.add(inbound)
        inbound_by_tag[tag] = inbound
        created += 1

    session.flush()
    report["inbounds"] = created
    print(f"  перенесено: {created}")
    if not xray_inbounds:
        print(
            "  Параметры не заданы (нет --xray-config): подключения созданы "
            "выключенными, заполните порт и ключи в панели."
        )
    else:
        derived = sum(
            1
            for inbound in inbound_by_tag.values()
            if (inbound.settings or {}).get("publicKey")
            and (inbound.settings or {}).get("privateKey")
        )
        if derived:
            print(f"  publicKey для REALITY вычислен из приватного: {derived}")
        stuck = [
            inbound.tag
            for inbound in inbound_by_tag.values()
            if (inbound.settings or {}).get("privateKey")
            and not (inbound.settings or {}).get("publicKey")
        ]
        if stuck:
            print(
                "  Не удалось вычислить publicKey (ключ в непонятном формате): "
                + ", ".join(stuck)
            )

    # 4. Хосты --------------------------------------------------------------
    print("\n[4/6] Хосты ссылок")
    created = 0
    for row in source.rows("hosts"):
        tag = row.get("inbound_tag")
        inbound = inbound_by_tag.get(tag)
        if inbound is None:
            continue
        security_raw = _enum_value(row.get("security"), "")
        session.add(
            Host(
                inbound_id=inbound.id,
                remark=row.get("remark") or "{node}",
                security=SecurityType(security_raw)
                if security_raw in {item.value for item in SecurityType}
                else None,
                address=row.get("address") or None,
                port=row.get("port"),
                sni=row.get("sni") or None,
                host=row.get("host") or None,
                path=row.get("path") or None,
                alpn=_enum_value(row.get("alpn"), "") or None,
                fingerprint=_enum_value(row.get("fingerprint"), "") or None,
                allowinsecure=bool(row.get("allowinsecure")),
                is_disabled=bool(row.get("is_disabled")),
            )
        )
        created += 1
    report["hosts"] = created
    print(f"  перенесено: {created}")

    # 5. Пользователи и ключи ----------------------------------------------
    print("\n[5/6] Пользователи")
    proxies_by_user: Dict[int, List[Dict[str, Any]]] = {}
    for row in source.rows("proxies"):
        proxies_by_user.setdefault(row.get("user_id"), []).append(row)

    all_inbounds = list(session.scalars(select(Inbound)).all())
    created = skipped = 0

    user_rows = source.rows("users")
    if limit:
        # Для тестовой панели вся база обычно не нужна: хватает нескольких
        # аккаунтов, чтобы посмотреть на подписки и ссылки.
        user_rows = user_rows[:limit]
        print(f"  ограничение: переносим только первых {limit}")

    for row in user_rows:
        username = row.get("username")
        if not username:
            continue
        if session.scalar(select(User).where(User.username == username)):
            skipped += 1
            continue

        status_raw = _enum_value(row.get("status"), "active")
        strategy_raw = _enum_value(row.get("data_limit_reset_strategy"), "no_reset")

        user = User(
            username=username,
            status=UserStatus(status_raw)
            if status_raw in {item.value for item in UserStatus}
            else UserStatus.active,
            used_traffic=int(row.get("used_traffic") or 0),
            lifetime_used_traffic=int(row.get("used_traffic") or 0),
            data_limit=int(row["data_limit"]) if row.get("data_limit") else None,
            data_limit_reset_strategy=DataLimitResetStrategy(strategy_raw)
            if strategy_raw in {item.value for item in DataLimitResetStrategy}
            else DataLimitResetStrategy.no_reset,
            expire=int(row["expire"]) if row.get("expire") else None,
            note=row.get("note"),
            created_at=_as_datetime(row.get("created_at")) or datetime.utcnow(),
            sub_revoked_at=_as_datetime(row.get("sub_revoked_at")),
            sub_updated_at=_as_datetime(row.get("sub_updated_at")),
            sub_last_user_agent=row.get("sub_last_user_agent"),
            online_at=_as_datetime(row.get("online_at")),
            last_status_change=_as_datetime(row.get("last_status_change")),
        )

        protocols = set()
        for proxy_row in proxies_by_user.get(row.get("id"), []):
            protocol_raw = _enum_value(proxy_row.get("type"), "vless").lower()
            if protocol_raw not in {item.value for item in ProxyType}:
                continue
            protocol = ProxyType(protocol_raw)
            protocols.add(protocol)

            raw_settings = proxy_row.get("settings")
            if isinstance(raw_settings, str):
                try:
                    raw_settings = json.loads(raw_settings)
                except json.JSONDecodeError:
                    raw_settings = {}
            user.proxies.append(
                UserProxy(protocol=protocol, settings=raw_settings or {})
            )

        # Marzban хранит доступные inbound'ы как «все минус исключённые»,
        # поэтому выдаём все подключения подходящих протоколов.
        user.inbounds = [
            inbound for inbound in all_inbounds if inbound.protocol in protocols
        ]

        session.add(user)
        created += 1

    report["users"] = created
    print(f"  перенесено: {created}, уже были в панели: {skipped}")

    # 6. Ноды ---------------------------------------------------------------
    print("\n[6/6] Серверы")
    created = 0
    for row in source.rows("nodes"):
        name = row.get("name")
        if not name or session.scalar(select(Node).where(Node.name == name)):
            continue
        session.add(
            Node(
                name=name,
                address=row.get("address") or "",
                agent_port=8443,
                # Токен агента задаётся при установке нашего агента на сервер.
                agent_token="",
                status=NodeStatus.disabled,
                is_enabled=False,
                usage_coefficient=float(row.get("usage_coefficient") or 1.0),
                uplink=int(row.get("uplink") or 0),
                downlink=int(row.get("downlink") or 0),
                message="Перенесено из Marzban: установите агента и укажите токен",
            )
        )
        created += 1
    report["nodes"] = created
    print(f"  перенесено: {created} (все выключены — нужен агент и токен)")

    if dry_run:
        session.rollback()
        print("\n--dry-run: изменения откачены, база панели не тронута.")
    else:
        session.commit()
        print("\nГотово, данные записаны.")

    print("\nИтог: " + ", ".join(f"{key}={value}" for key, value in report.items()))


def main() -> None:
    parser = argparse.ArgumentParser(description="Перенос базы Marzban в панель")
    parser.add_argument(
        "--source",
        required=True,
        help="URL базы Marzban, напр. mysql+pymysql://user:pass@host/marzban "
        "или sqlite:////var/lib/marzban/db.sqlite3",
    )
    parser.add_argument(
        "--target",
        default=settings.sync_database_url,
        help="URL базы панели (по умолчанию — из DATABASE_URL)",
    )
    parser.add_argument(
        "--xray-config",
        default=None,
        help="Путь к xray_config.json Marzban — оттуда берутся параметры inbound'ов",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Прогнать без записи, только показать, что будет перенесено",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Перенести только первых N пользователей — для тестовой панели",
    )
    parser.add_argument(
        "--write-env",
        nargs="?",
        const=".env",
        default=None,
        metavar="ПУТЬ",
        help="Записать SUBSCRIPTION_SECRET прямо в .env (по умолчанию ./.env)",
    )
    args = parser.parse_args()

    print(f"Источник: {args.source}")
    print(f"Приёмник: {args.target}")

    xray_inbounds = load_xray_inbounds(args.xray_config)
    if xray_inbounds:
        print(f"Из xray_config.json прочитано подключений: {len(xray_inbounds)}")

    source = MarzbanSource(args.source)
    target_engine = create_engine(args.target)
    Base.metadata.create_all(target_engine)

    with Session(target_engine) as session:
        migrate(
            source,
            session,
            xray_inbounds,
            args.dry_run,
            args.limit,
            Path(args.write_env) if args.write_env else None,
        )


if __name__ == "__main__":
    main()
