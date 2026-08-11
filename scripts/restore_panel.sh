#!/usr/bin/env bash
# Разворачивает архив scripts/backup_panel.sh на этом сервере: заменяет базу
# и переносит настройки, сохраняя local-подключение к базе и адреса панели.
#
#   bash scripts/restore_panel.sh /root/vpn-panel-....tar.gz
#   bash scripts/restore_panel.sh /root/архив.tar.gz -y     # без вопросов
#
# Перед заменой скрипт сам делает снимок текущей базы — если что-то пойдёт
# не так, откатиться можно им.
#
# Что берётся из архива: пользователи, серверы, подключения, хосты, журналы,
# а также ключи из .env — SECRET_KEY и SUBSCRIPTION_SECRET. Именно они
# отвечают за то, что старые ссылки подписок продолжат открываться.
#
# Что остаётся от этого сервера: DATABASE_URL (у новой машины своя база),
# PANEL_URL и SUBSCRIPTION_BASE_URL — адреса задаются отдельно,
# scripts/setup_domain.sh.

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$INSTALL_DIR/.env"
SERVICE_NAME="vpn-panel"
ARCHIVE="${1:-}"
ASSUME_YES=0
[[ "${2:-}" == "-y" ]] && ASSUME_YES=1

if [[ "$EUID" -ne 0 ]]; then
  echo "Запускать нужно от root" >&2
  exit 1
fi
if [[ -z "$ARCHIVE" || ! -f "$ARCHIVE" ]]; then
  echo "Использование: bash scripts/restore_panel.sh <архив.tar.gz> [-y]" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Не вижу $ENV_FILE — сначала поставьте панель: bash scripts/install_panel.sh" >&2
  exit 1
fi

env_value() {
  # env_value КЛЮЧ [ФАЙЛ]
  sed -n "s/^$1=//p" "${2:-$ENV_FILE}" | tail -1
}

DB_URL="$(env_value DATABASE_URL)"
if [[ -z "$DB_URL" ]]; then
  echo "В .env нет DATABASE_URL" >&2
  exit 1
fi
DB_URL="${DB_URL/+asyncpg/}"

if ! command -v psql >/dev/null 2>&1; then
  echo "==> Ставим клиент Postgres"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq postgresql-client >/dev/null
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Распаковываем архив"
tar -xzf "$ARCHIVE" -C "$WORK"
BOX="$WORK/panel-backup"
if [[ ! -f "$BOX/db.sql" || ! -f "$BOX/env" ]]; then
  echo "Это не архив панели: внутри нет db.sql и env" >&2
  exit 1
fi
[[ -f "$BOX/manifest.txt" ]] && cat "$BOX/manifest.txt"

# Секрет подписи — единственное, без чего переезд бессмыслен: с чужим
# секретом ни одна выданная ранее ссылка не откроется.
NEW_SECRET="$(env_value SUBSCRIPTION_SECRET "$BOX/env")"
NEW_KEY="$(env_value SECRET_KEY "$BOX/env")"
if [[ -z "$NEW_SECRET" && -z "$NEW_KEY" ]]; then
  echo "В архиве нет ни SUBSCRIPTION_SECRET, ни SECRET_KEY — ссылки подписок перестанут работать" >&2
  exit 1
fi

echo
echo "База ${DB_URL##*/} на этом сервере будет заменена содержимым архива."
if [[ "$ASSUME_YES" != "1" ]]; then
  if [[ ! -t 0 ]]; then
    echo "Нет терминала для подтверждения — запустите с ключом -y" >&2
    exit 1
  fi
  read -rp "Продолжаем? [y/N]: " answer
  [[ "$answer" =~ ^[yYдД] ]] || { echo "Отменено."; exit 1; }
fi

echo "==> Снимок текущей базы (на случай отката)"
ROLLBACK="/root/vpn-panel-before-restore-$(date +%Y%m%d-%H%M%S).sql"
if pg_dump --no-owner --no-privileges -f "$ROLLBACK" "$DB_URL" 2>/dev/null; then
  gzip -f "$ROLLBACK"
  chmod 600 "${ROLLBACK}.gz"
  echo "  ${ROLLBACK}.gz"
else
  echo "  база пуста или недоступна — снимок не понадобился"
  rm -f "$ROLLBACK"
fi

echo "==> Останавливаем панель"
systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true

echo "==> Чистим схему и заливаем базу"
# Дамп сделан с --clean, но на пустой схеме этого мало: старые таблицы могли
# появиться от свежей установки, и лишние строки смешались бы с переносимыми.
psql -v ON_ERROR_STOP=1 -qc 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' "$DB_URL"
if ! psql -v ON_ERROR_STOP=1 -q -f "$BOX/db.sql" "$DB_URL" >/dev/null; then
  cat >&2 <<EOF

Залить базу не удалось. Данные этого сервера остались в снимке:
  ${ROLLBACK}.gz
Вернуть их:
  gunzip -c ${ROLLBACK}.gz | psql "\$(вырезать DATABASE_URL из .env)"
EOF
  systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
  exit 1
fi

echo "==> Переносим настройки"
cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%s)"
LOCAL_DB="$(env_value DATABASE_URL)"
LOCAL_PANEL="$(env_value PANEL_URL)"
LOCAL_SUB="$(env_value SUBSCRIPTION_BASE_URL)"

cp "$BOX/env" "$ENV_FILE"
set_env() {
  local key="$1" value="$2"
  [[ -z "$value" ]] && return 0
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}
set_env DATABASE_URL "$LOCAL_DB"
set_env PANEL_URL "$LOCAL_PANEL"
set_env SUBSCRIPTION_BASE_URL "$LOCAL_SUB"
chmod 600 "$ENV_FILE"

echo "==> Запускаем панель"
systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
sleep 4

# Без «|| true» скрипт обрывается на полпути: при pipefail sed возвращает
# ошибку, если юнита нет, и до итогового отчёта дело не доходит.
APP_PORT="$(sed -n 's/.*--port \([0-9]*\).*/\1/p' "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null | head -1 || true)"
APP_PORT="${APP_PORT:-8000}"
CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
  "http://127.0.0.1:${APP_PORT}/healthz" 2>/dev/null || true)"

count_rows() { psql -tAqc "$1" "$DB_URL" 2>/dev/null | tr -d ' ' || true; }
USERS="$(count_rows 'select count(*) from users')"
NODES="$(count_rows 'select count(*) from nodes')"

cat <<EOF

======================================================================
Перенесено: пользователей ${USERS:-?}, серверов ${NODES:-?}
Панель отвечает на 127.0.0.1:${APP_PORT}/healthz: ${CODE:-000}

Настройки на этом сервере:
  PANEL_URL             = $(env_value PANEL_URL)
  SUBSCRIPTION_BASE_URL = $(env_value SUBSCRIPTION_BASE_URL)
  SUBSCRIPTION_PATH     = $(env_value SUBSCRIPTION_PATH)

Дальше:
  1. Домен и сертификат:
       bash scripts/setup_domain.sh <домен панели> --sub <домен подписок>
     Старый домен подписок нужно оставить рабочим — ключ --also,
     см. docs/GOLIVE.md.
  2. Проверить, что открывается чужая ссылка подписки (любая из «Пользователи»).
  3. Серверы в панели переопрашиваются сами; если агент закрыт файрволом
     по адресу прежней панели — поправить правило ufw на ноде.

Откат: gunzip -c ${ROLLBACK}.gz | psql "$(env_value DATABASE_URL | sed 's/+asyncpg//')"
======================================================================
EOF
