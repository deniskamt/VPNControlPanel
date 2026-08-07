#!/usr/bin/env bash
# Удаление панели: systemd-сервис, окружение Python, .env и, по желанию, база.
# Нужен, когда пробную установку хочется снести и поставить заново начисто.
#
#   bash scripts/uninstall_panel.sh                 # спросит про базу и файлы
#   DROP_DATABASE=1 PURGE=1 bash scripts/uninstall_panel.sh -y   # снести всё молча
#
# Переменные:
#   DROP_DATABASE=1  — удалить базу и её пользователя (данные не вернуть)
#   PURGE=1          — удалить и сам каталог с исходниками
#   -y               — не задавать вопросов
#
# Ноды скрипт не трогает: агент удаляется на самом сервере командой
#   systemctl disable --now vpn-agent && rm -rf /opt/vpn-agent

set -euo pipefail

SERVICE_NAME="vpn-panel"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ASSUME_YES=0
[[ "${1:-}" == "-y" ]] && ASSUME_YES=1

if [[ "$EUID" -ne 0 ]]; then
  echo "Запускать нужно от root" >&2
  exit 1
fi

confirm() {
  # confirm "Вопрос"  → 0, если пользователь согласился
  [[ "$ASSUME_YES" == "1" ]] && return 0
  [[ ! -t 0 ]] && return 1
  local answer
  read -rp "$1 [y/N]: " answer
  [[ "$answer" =~ ^[yYдД] ]]
}

# Каталог установки берём из юнита: панель могла быть установлена куда угодно.
INSTALL_DIR=""
if [[ -f "$UNIT_FILE" ]]; then
  INSTALL_DIR="$(sed -n 's/^WorkingDirectory=//p' "$UNIT_FILE" | tail -1)"
fi
if [[ -z "$INSTALL_DIR" ]]; then
  INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

echo "Панель: ${INSTALL_DIR}"

echo "==> Останавливаем сервис"
if [[ -f "$UNIT_FILE" ]]; then
  # Ни одна ошибка systemd не должна прервать удаление на полпути:
  # иначе останутся и файлы, и база.
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "  сервис ${SERVICE_NAME} удалён"
else
  echo "  сервис не найден — пропускаем"
fi

# Имя базы и пользователя достаём из .env, чтобы не гадать.
DB_NAME=""
DB_USER=""
if [[ -f "$INSTALL_DIR/.env" ]]; then
  DB_URL="$(sed -n 's/^DATABASE_URL=//p' "$INSTALL_DIR/.env" | tail -1)"
  if [[ "$DB_URL" =~ ^postgresql(\+asyncpg)?://([^:]+):[^@]*@[^/]+/(.+)$ ]]; then
    DB_USER="${BASH_REMATCH[2]}"
    DB_NAME="${BASH_REMATCH[3]}"
  fi
fi

echo "==> База данных"
if [[ -z "$DB_NAME" ]]; then
  echo "  не удалось определить базу из .env — пропускаем"
elif [[ "${DROP_DATABASE:-0}" == "1" ]] || confirm "  Удалить базу «${DB_NAME}» вместе со всеми пользователями VPN?"; then
  su postgres -c "dropdb --if-exists ${DB_NAME}" >/dev/null 2>&1 || true
  if [[ -n "$DB_USER" && "$DB_USER" != "postgres" ]]; then
    su postgres -c "psql -qc \"DROP ROLE IF EXISTS ${DB_USER}\"" >/dev/null 2>&1 || true
  fi
  echo "  база ${DB_NAME} удалена"
else
  echo "  база ${DB_NAME} сохранена"
fi

echo "==> Файлы"
rm -rf "$INSTALL_DIR/.venv"
rm -f "$INSTALL_DIR/.env" "$INSTALL_DIR"/.env.bak.*
echo "  окружение и .env удалены"

if [[ "${PURGE:-0}" == "1" ]] || confirm "  Удалить сам каталог ${INSTALL_DIR}?"; then
  # Каталог может быть текущим для этого процесса — уходим из него заранее.
  cd /
  rm -rf "$INSTALL_DIR"
  echo "  каталог удалён"
else
  echo "  исходники оставлены в ${INSTALL_DIR}"
fi

cat <<EOF

Готово. Панели на этом сервере больше нет.

Поставить заново:
  git clone https://github.com/deniskamt/VPNControlPanel.git /opt/vpn-panel
  cd /opt/vpn-panel
  bash scripts/install_panel.sh
EOF
