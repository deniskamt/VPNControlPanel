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
#   SKIP_SYSTEMD=1      — не трогать systemd (для ручной настройки)

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="vpn-panel"
APP_PORT="${APP_PORT:-8000}"

if [[ "$EUID" -ne 0 ]]; then
  echo "Запускать нужно от root" >&2
  exit 1
fi

if [[ ! -f "$INSTALL_DIR/app/main.py" ]]; then
  echo "Не вижу исходников панели в $INSTALL_DIR" >&2
  exit 1
fi

ask() {
  # ask ПЕРЕМЕННАЯ "Вопрос" "значение по умолчанию"
  local name="$1" prompt="$2" default="${3:-}" value="${!1:-}"
  if [[ -n "$value" ]]; then
    printf -v "$name" '%s' "$value"
    return
  fi
  if [[ ! -t 0 ]]; then
    printf -v "$name" '%s' "$default"
    return
  fi
  read -rp "$prompt${default:+ [$default]}: " value
  printf -v "$name" '%s' "${value:-$default}"
}

echo "==> Ставим системные пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-dev build-essential curl ca-certificates >/dev/null

echo "==> Готовим базу данных"
if [[ -z "${DATABASE_URL:-}" ]]; then
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
  fi

  DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME"
  echo "  база $DB_NAME готова"
else
  echo "  используем внешнюю базу из DATABASE_URL"
fi

echo "==> Настройки панели"
DEFAULT_ADDRESS="$(hostname -I 2>/dev/null | awk '{print $1}')"
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

ask SUBSCRIPTION_ADDRESS "Адрес в ссылках подписок" "$PANEL_URL"
ask SUBSCRIPTION_PATH "Префикс пути подписки" "c"
ask ADMIN_USERNAME "Логин администратора" "admin"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')}"

# Адрес подписок можно указать и без схемы — дополним сами.
if [[ "$SUBSCRIPTION_ADDRESS" != http://* && "$SUBSCRIPTION_ADDRESS" != https://* ]]; then
  SUBSCRIPTION_ADDRESS="${PANEL_SCHEME}://${SUBSCRIPTION_ADDRESS}"
fi

echo "==> Создаём окружение Python"
if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
  python3 -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

echo "==> Пишем .env"
if [[ -f "$INSTALL_DIR/.env" ]]; then
  cp "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.bak.$(date +%s)"
  echo "  прежний .env сохранён рядом с суффиксом .bak"
fi

SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
cat > "$INSTALL_DIR/.env" <<EOF
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
SUBSCRIPTION_SECRET=
SUBSCRIPTION_TITLE=NexloVPN
SUBSCRIPTION_UPDATE_INTERVAL=12

TELEGRAM_BOT_TOKEN=
TELEGRAM_ADMIN_IDS=
NOTIFY_NODE_STATUS=true

NODE_POLL_INTERVAL=30
ENFORCE_INTERVAL=60
NODE_TIMEOUT=10
EOF
chmod 600 "$INSTALL_DIR/.env"

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

  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  sleep 3
  systemctl --no-pager --lines=15 status "$SERVICE_NAME" || true
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

cat <<EOF

======================================================================
Панель установлена в ${INSTALL_DIR}
${WARNING}

Вход:      ${PANEL_URL}
Логин:     ${ADMIN_USERNAME}
Пароль:    ${ADMIN_PASSWORD}
           (сохраните — второй раз он не покажется)

Подписки:  ${SUBSCRIPTION_ADDRESS}/${SUBSCRIPTION_PATH}/<token>

Дальше:
${NEXT_STEPS}

Логи:      journalctl -u ${SERVICE_NAME} -f
Рестарт:   systemctl restart ${SERVICE_NAME}
======================================================================
EOF
