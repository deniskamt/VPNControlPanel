#!/usr/bin/env bash
# Снимок панели одним файлом: база целиком плюс .env с ключами.
#
#   bash scripts/backup_panel.sh                      # → /root/vpn-panel-<хост>-<дата>.tar.gz
#   bash scripts/backup_panel.sh /root/переезд.tar.gz # свой путь
#
# Архив разворачивается на другом сервере командой
#   bash scripts/restore_panel.sh <архив>
#
# ВНИМАНИЕ: внутри лежат ключи всех пользователей и секрет подписи подписок.
# Файл равнозначен доступу ко всему VPN — храните его только на время
# переезда и потом удалите с обоих серверов (shred -u <архив>).

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$INSTALL_DIR/.env"
TARGET="${1:-}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Не вижу $ENV_FILE — панель здесь не установлена" >&2
  exit 1
fi

env_value() {
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

DB_URL="$(env_value DATABASE_URL)"
if [[ -z "$DB_URL" ]]; then
  echo "В .env нет DATABASE_URL — нечего выгружать" >&2
  exit 1
fi
# pg_dump не понимает диалект SQLAlchemy, ему нужен обычный postgresql://.
DB_URL="${DB_URL/+asyncpg/}"

if ! command -v pg_dump >/dev/null 2>&1; then
  echo "==> Ставим клиент Postgres (pg_dump)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq postgresql-client >/dev/null
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname -s 2>/dev/null || echo panel)"
TARGET="${TARGET:-/root/vpn-panel-${HOST}-${STAMP}.tar.gz}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BOX="$WORK/panel-backup"
mkdir -p "$BOX"

echo "==> Выгружаем базу"
# --no-owner/--no-privileges: на новом сервере пользователь базы называется
# иначе, и восстановление не должно об это спотыкаться.
if ! pg_dump --no-owner --no-privileges --clean --if-exists \
     -f "$BOX/db.sql" "$DB_URL"; then
  echo "Не удалось выгрузить базу. Проверьте DATABASE_URL в .env" >&2
  exit 1
fi

echo "==> Кладём .env"
cp "$ENV_FILE" "$BOX/env"

# Пригодится, когда архив найдётся через полгода и будет непонятно, чей он.
REVISION="$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "неизвестно")"
count_rows() { psql -tAqc "$1" "$DB_URL" 2>/dev/null | tr -d ' ' || true; }
USERS="$(count_rows 'select count(*) from users')"
NODES="$(count_rows 'select count(*) from nodes')"
INBOUNDS="$(count_rows 'select count(*) from inbounds')"

cat > "$BOX/manifest.txt" <<EOF
Снимок панели VPN
дата:          $(date '+%Y-%m-%d %H:%M:%S %Z')
сервер:        $(hostname -f 2>/dev/null || hostname)
версия кода:   ${REVISION}
пользователей: ${USERS:-?}
серверов:      ${NODES:-?}
подключений:   ${INBOUNDS:-?}
подписки:      $(env_value SUBSCRIPTION_BASE_URL)/$(env_value SUBSCRIPTION_PATH)/<token>
EOF

echo "==> Пакуем"
tar -czf "$TARGET" -C "$WORK" panel-backup
chmod 600 "$TARGET"
SIZE="$(du -h "$TARGET" | cut -f1)"

cat <<EOF

======================================================================
Архив: ${TARGET}  (${SIZE})

$(cat "$BOX/manifest.txt")

Перенести на другой сервер:
  scp ${TARGET} root@<новый сервер>:/root/

И там развернуть:
  cd /opt/vpn-panel && bash scripts/restore_panel.sh /root/$(basename "$TARGET")

В архиве — ключи всех пользователей и секрет подписи подписок. Как только
переезд проверен, удалите его с обоих серверов:
  shred -u ${TARGET}
======================================================================
EOF
