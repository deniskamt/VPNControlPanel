#!/usr/bin/env bash
# Установка панели на сервер (Ubuntu/Debian): Postgres, окружение Python,
# systemd-сервис. Nginx и сертификат ставятся отдельным шагом — см. docs/DEPLOY.md.
#
# Запускать из каталога с исходниками панели, от root:
#
#   git clone https://github.com/deniskamt/VPNControlPanel.git /opt/vpn-panel
#   cd /opt/vpn-panel
#   bash scripts/install_panel.sh
#
# Скрипт можно запускать повторно: если рядом уже есть .env, прежние ключи,
# база и пароли сохраняются, обновляются только зависимости и сервис.
# Полная переустановка с новыми ключами — REINSTALL=1 (старые ссылки подписок
# при этом перестанут работать, если SUBSCRIPTION_SECRET не задан явно).
#
# Для пробной установки без домена достаточно указать IP сервера — скрипт сам
# перейдёт на http, поднимет панель на всех интерфейсах и не будет ждать nginx.
#
# Переменные (все необязательные, скрипт спросит недостающее):
#   PANEL_ADDRESS       — домен или IP панели, напр. panel.example.com или 1.2.3.4
#   PANEL_SCHEME        — http или https; по умолчанию http для IP, https для домена
#   APP_PORT            — порт панели, по умолчанию 8000
#   SUBSCRIPTION_ADDRESS— адрес в ссылках подписок (для переезда с Marzban — его домен)
#   SUBSCRIPTION_PATH   — префикс пути подписки, по умолчанию c
#   ADMIN_USERNAME      — логин первого админа, по умолчанию admin
#   ADMIN_PASSWORD      — пароль первого админа, по умолчанию генерируется
#   DATABASE_URL        — если база уже есть; иначе поднимается локальный Postgres
#   REINSTALL=1         — не сохранять прежние ключи и настройки
#   SKIP_SYSTEMD=1      — не трогать systemd (для ручной настройки)

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="vpn-panel"
ENV_FILE="$INSTALL_DIR/.env"

if [[ "$EUID" -ne 0 ]]; then
  echo "Запускать нужно от root" >&2
  exit 1
fi

if [[ ! -f "$INSTALL_DIR/app/main.py" ]]; then
  echo "Не вижу исходников панели в $INSTALL_DIR" >&2
  exit 1
fi

# Значение из уже существующего .env (пусто, если файла или ключа нет).
env_value() {
  [[ -f "$ENV_FILE" ]] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

# Адреса приезжают из буфера обмена, а вместе с ними — перевод строки от
# Windows, пробелы и невидимые символы. Один такой символ внутри IP ломает
# его распознавание, и панель молча настраивается на https вместо http.
sanitize_host() {
  printf '%s' "$1" | tr -d '[:space:]' | tr -cd 'A-Za-z0-9.:/_-'
}

ask() {
  # ask ПЕРЕМЕННАЯ "Вопрос" "значение по умолчанию"
  local name="$1" prompt="$2" default="${3:-}" value="${!1:-}"
  if [[ -n "$value" ]]; then
    printf -v "$name" '%s' "$(sanitize_host "$value")"
    return
  fi
  if [[ ! -t 0 ]]; then
    printf -v "$name" '%s' "$(sanitize_host "$default")"
    return
  fi
  read -rp "$prompt${default:+ [$default]}: " value
  printf -v "$name" '%s' "$(sanitize_host "${value:-$default}")"
}

IS_UPGRADE=0
if [[ -f "$ENV_FILE" && "${REINSTALL:-0}" != "1" ]]; then
  IS_UPGRADE=1
  echo "==> Панель здесь уже установлена — обновляем её"
  echo "    Ключи, база и пароль администратора сохраняются."
  echo "    Полная переустановка с нуля: REINSTALL=1 bash scripts/install_panel.sh"

  # Секреты не трогаем: SECRET_KEY подписывает сессии, а при пустом
  # SUBSCRIPTION_SECRET — ещё и токены подписок. Его смена ломает выданные ссылки.
  SECRET_KEY="${SECRET_KEY:-$(env_value SECRET_KEY)}"
  SUBSCRIPTION_SECRET="${SUBSCRIPTION_SECRET:-$(env_value SUBSCRIPTION_SECRET)}"
  DATABASE_URL="${DATABASE_URL:-$(env_value DATABASE_URL)}"

  # Остальные настройки переносим как есть, чтобы не потерять правки руками.
  SUBSCRIPTION_TITLE="${SUBSCRIPTION_TITLE:-$(env_value SUBSCRIPTION_TITLE)}"
  SUBSCRIPTION_UPDATE_INTERVAL="${SUBSCRIPTION_UPDATE_INTERVAL:-$(env_value SUBSCRIPTION_UPDATE_INTERVAL)}"
  TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-$(env_value TELEGRAM_BOT_TOKEN)}"
  TELEGRAM_ADMIN_IDS="${TELEGRAM_ADMIN_IDS:-$(env_value TELEGRAM_ADMIN_IDS)}"
  NOTIFY_NODE_STATUS="${NOTIFY_NODE_STATUS:-$(env_value NOTIFY_NODE_STATUS)}"
  NODE_POLL_INTERVAL="${NODE_POLL_INTERVAL:-$(env_value NODE_POLL_INTERVAL)}"
  ENFORCE_INTERVAL="${ENFORCE_INTERVAL:-$(env_value ENFORCE_INTERVAL)}"
  NODE_TIMEOUT="${NODE_TIMEOUT:-$(env_value NODE_TIMEOUT)}"

  OLD_PANEL_URL="$(env_value PANEL_URL)"
  OLD_SUBSCRIPTION_URL="$(env_value SUBSCRIPTION_BASE_URL)"
  OLD_ADMIN_USERNAME="$(env_value ADMIN_USERNAME)"
  OLD_SUBSCRIPTION_PATH="$(env_value SUBSCRIPTION_PATH)"
fi

SECRET_KEY="${SECRET_KEY:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')}"
SUBSCRIPTION_SECRET="${SUBSCRIPTION_SECRET:-}"
SUBSCRIPTION_TITLE="${SUBSCRIPTION_TITLE:-NexloVPN}"
SUBSCRIPTION_UPDATE_INTERVAL="${SUBSCRIPTION_UPDATE_INTERVAL:-12}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_ADMIN_IDS="${TELEGRAM_ADMIN_IDS:-}"
NOTIFY_NODE_STATUS="${NOTIFY_NODE_STATUS:-true}"
NODE_POLL_INTERVAL="${NODE_POLL_INTERVAL:-30}"
ENFORCE_INTERVAL="${ENFORCE_INTERVAL:-60}"
NODE_TIMEOUT="${NODE_TIMEOUT:-10}"
APP_PORT="${APP_PORT:-8000}"

echo "==> Ставим системные пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-dev build-essential curl ca-certificates >/dev/null

echo "==> Готовим базу данных"
if [[ -n "${DATABASE_URL:-}" ]]; then
  echo "  используем уже настроенную базу"
else
  apt-get install -y -qq postgresql >/dev/null
  # В контейнерах без systemd поднимаем кластер напрямую.
  if command -v systemctl >/dev/null && systemctl is-system-running --quiet 2>/dev/null; then
    systemctl enable --now postgresql
  else
    service postgresql start || true
  fi

  DB_NAME="${DB_NAME:-vpnpanel}"
  DB_USER="${DB_USER:-vpnpanel}"
  DB_PASSWORD="${DB_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')}"

  if su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'\"" | grep -q 1; then
    echo "  пользователь $DB_USER уже есть — обновляем пароль"
    su postgres -c "psql -qc \"ALTER ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASSWORD';\"" >/dev/null
  else
    su postgres -c "psql -qc \"CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASSWORD';\"" >/dev/null
  fi

  if ! su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='$DB_NAME'\"" | grep -q 1; then
    su postgres -c "createdb -O $DB_USER $DB_NAME"
  else
    echo "  база $DB_NAME уже существует — данные сохраняем"
  fi

  DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME"
fi

echo "==> Настройки панели"
DEFAULT_ADDRESS="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -n "${OLD_PANEL_URL:-}" ]]; then
  # Предлагаем то, что уже настроено: адрес без схемы и без порта.
  DEFAULT_ADDRESS="${OLD_PANEL_URL#*://}"
  DEFAULT_ADDRESS="${DEFAULT_ADDRESS%%:*}"
  [[ "$OLD_PANEL_URL" == https://* ]] && PANEL_SCHEME="${PANEL_SCHEME:-https}"
fi
ask PANEL_ADDRESS "Домен или IP панели" "${DEFAULT_ADDRESS:-localhost}"

# Без домена сертификат взять неоткуда, поэтому для голого IP работаем по http
# и слушаем все интерфейсы — nginx в такой схеме не нужен.
if [[ "$PANEL_ADDRESS" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$PANEL_ADDRESS" == "localhost" ]]; then
  PANEL_SCHEME="${PANEL_SCHEME:-http}"
else
  PANEL_SCHEME="${PANEL_SCHEME:-https}"
fi

if [[ "$PANEL_SCHEME" == "http" ]]; then
  BIND_HOST="0.0.0.0"
  PANEL_URL="http://${PANEL_ADDRESS}:${APP_PORT}"
else
  # За nginx: панель слушает только локально, наружу её пускает он.
  BIND_HOST="127.0.0.1"
  PANEL_URL="https://${PANEL_ADDRESS}"
fi

ask SUBSCRIPTION_ADDRESS "Адрес в ссылках подписок" "${OLD_SUBSCRIPTION_URL:-$PANEL_URL}"
ask SUBSCRIPTION_PATH "Префикс пути подписки" "${OLD_SUBSCRIPTION_PATH:-c}"
ask ADMIN_USERNAME "Логин администратора" "${OLD_ADMIN_USERNAME:-admin}"

# Адрес подписок можно указать и без схемы — дополним сами.
if [[ "$SUBSCRIPTION_ADDRESS" != http://* && "$SUBSCRIPTION_ADDRESS" != https://* ]]; then
  SUBSCRIPTION_ADDRESS="${PANEL_SCHEME}://${SUBSCRIPTION_ADDRESS}"
fi

# Пароль имеет смысл только для самого первого запуска: дальше он живёт
# в базе, и переменная окружения на него уже не влияет.
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')}"

echo "==> Создаём окружение Python"
echo "  Python: $(python3 --version 2>&1)"
# Прошлая попытка установки могла оставить недоделанное окружение —
# на нём pip ведёт себя непредсказуемо, проще пересоздать.
if [[ -d "$INSTALL_DIR/.venv" && ! -x "$INSTALL_DIR/.venv/bin/pip" ]]; then
  echo "  прежнее окружение повреждено — создаём заново"
  rm -rf "$INSTALL_DIR/.venv"
fi
if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
  python3 -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
if ! "$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"; then
  echo >&2
  echo "Не удалось поставить зависимости." >&2
  echo "Если pip пытался собирать asyncpg, greenlet или pydantic-core из" >&2
  echo "исходников — обновите код панели (git pull) и повторите: в свежей" >&2
  echo "версии версии пакетов подобраны так, чтобы ставиться готовыми" >&2
  echo "колёсами на любой Python начиная с 3.11." >&2
  exit 1
fi

echo "==> Пишем .env"
if [[ -f "$ENV_FILE" ]]; then
  cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%s)"
  echo "  прежний .env сохранён рядом с суффиксом .bak"
fi

cat > "$ENV_FILE" <<EOF
SECRET_KEY=${SECRET_KEY}
PANEL_URL=${PANEL_URL}
DEBUG=false

DATABASE_URL=${DATABASE_URL}

ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}

SUBSCRIPTION_BASE_URL=${SUBSCRIPTION_ADDRESS}
SUBSCRIPTION_PATH=${SUBSCRIPTION_PATH}
# ВАЖНО: при переходе с Marzban сюда нужно вписать секрет из таблицы jwt
# старой базы — его печатает scripts/migrate_from_marzban.py. Без этого
# выданные ранее ссылки подписок перестанут открываться.
SUBSCRIPTION_SECRET=${SUBSCRIPTION_SECRET}
SUBSCRIPTION_TITLE=${SUBSCRIPTION_TITLE}
SUBSCRIPTION_UPDATE_INTERVAL=${SUBSCRIPTION_UPDATE_INTERVAL}

TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
TELEGRAM_ADMIN_IDS=${TELEGRAM_ADMIN_IDS}
NOTIFY_NODE_STATUS=${NOTIFY_NODE_STATUS}

NODE_POLL_INTERVAL=${NODE_POLL_INTERVAL}
ENFORCE_INTERVAL=${ENFORCE_INTERVAL}
NODE_TIMEOUT=${NODE_TIMEOUT}
EOF
chmod 600 "$ENV_FILE"

# Есть ли уже администраторы: от этого зависит, что писать про пароль.
# Переменная ADMIN_PASSWORD влияет только на первый запуск, поэтому печатать
# сгенерированный пароль при обновлении нельзя — он не будет работать.
ADMINS_EXIST=0
ADMIN_LIST="$(cd "$INSTALL_DIR" && .venv/bin/python scripts/admin.py list 2>/dev/null || true)"
if [[ -n "$ADMIN_LIST" && "$ADMIN_LIST" != *"Администраторов нет"* ]]; then
  ADMINS_EXIST=1
fi

if [[ "${SKIP_SYSTEMD:-0}" != "1" ]]; then
  echo "==> Настраиваем systemd"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=VPN Control Panel
After=network.target postgresql.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/.venv/bin/uvicorn app.main:app \\
    --host ${BIND_HOST} --port ${APP_PORT} \\
    --proxy-headers --forwarded-allow-ips '*'
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  if systemctl daemon-reload >/dev/null 2>&1; then
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE_NAME"
    sleep 3
    systemctl --no-pager --lines=15 status "$SERVICE_NAME" || true
  else
    # Систем без systemd (контейнеры, WSL) — юнит записан, запускать нечем.
    echo "  systemd недоступен: запустите панель вручную"
    echo "  ${INSTALL_DIR}/.venv/bin/uvicorn app.main:app --host ${BIND_HOST} --port ${APP_PORT}"
  fi
fi

if [[ "$ADMINS_EXIST" == "1" ]]; then
  CREDENTIALS="Логин:     ${ADMIN_USERNAME} (пароль прежний, он хранится в базе)
Забыли?    cd ${INSTALL_DIR} && .venv/bin/python scripts/admin.py set-password --username ${ADMIN_USERNAME}"
else
  CREDENTIALS="Логин:     ${ADMIN_USERNAME}
Пароль:    ${ADMIN_PASSWORD}
           (сохраните — второй раз он не покажется)"
fi

if [[ "$PANEL_SCHEME" == "http" ]]; then
  NEXT_STEPS="  1. Открыть порт: ufw allow ${APP_PORT}/tcp
     (лучше только для своего адреса: ufw allow from <ваш IP> to any port ${APP_PORT})
  2. Создать подключение и сервер в панели, поставить агента
  3. Перед боевым запуском — домен и HTTPS, см. docs/DEPLOY.md"
  WARNING="ВНИМАНИЕ: панель работает по http, пароль и токены идут открытым
текстом. Это годится для проверки, но не для боевой установки."
else
  NEXT_STEPS="  1. Поставить nginx и сертификат — команды в docs/DEPLOY.md
  2. При переходе с Marzban: перенести базу и вписать SUBSCRIPTION_SECRET
     python scripts/migrate_from_marzban.py --source ... --dry-run
  3. Добавить серверы в панели и поставить на них агента"
  WARNING="Панель слушает 127.0.0.1:${APP_PORT} — наружу её пускает nginx."
fi

if [[ "$IS_UPGRADE" == "1" ]]; then
  NEXT_STEPS="  Обновление завершено, настройки и данные на месте.
  Изменить что-то ещё: nano ${ENV_FILE} && systemctl restart ${SERVICE_NAME}"
fi

cat <<EOF

======================================================================
Панель установлена в ${INSTALL_DIR}
${WARNING}

Вход:      ${PANEL_URL}
${CREDENTIALS}

Подписки:  ${SUBSCRIPTION_ADDRESS}/${SUBSCRIPTION_PATH}/<token>

Дальше:
${NEXT_STEPS}

Логи:      journalctl -u ${SERVICE_NAME} -f
Рестарт:   systemctl restart ${SERVICE_NAME}
======================================================================
EOF
