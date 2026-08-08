#!/usr/bin/env bash
# Установка агента панели на VPN-сервер: Xray-core + агент + systemd-сервис.
#
#   AGENT_TOKEN=<токен из панели> PANEL_URL=https://panel.example.com bash install_agent.sh
#
# Этой же командой агент обновляется: скрипт видит, что он уже установлен,
# переиспользует прежний токен и не качает Xray заново.
#
# Переменные:
#   AGENT_TOKEN  — токен из панели. При обновлении можно не указывать:
#                  берётся из agent.env
#   PANEL_URL    (обяз.) — адрес панели, откуда скачивается agent.py
#   AGENT_PORT   — порт агента, по умолчанию 8443
#   XRAY_VERSION — версия ядра, по умолчанию последняя
#   XRAY_FORCE=1 — переустановить Xray, даже если он уже стоит

set -euo pipefail

AGENT_TOKEN="${AGENT_TOKEN:-}"
PANEL_URL="${PANEL_URL:-}"
AGENT_PORT="${AGENT_PORT:-8443}"
XRAY_VERSION="${XRAY_VERSION:-latest}"
INSTALL_DIR="/opt/vpn-agent"
ENV_FILE="$INSTALL_DIR/agent.env"

# Что это — установка или обновление, решает наличие агента, а не Xray:
# ядро может быть уже поставлено чужим скриптом.
if [[ -f "$ENV_FILE" || -f "$INSTALL_DIR/agent.py" ]]; then
  IS_UPDATE=1
else
  IS_UPDATE=0
fi

# Обновление не должно требовать бегать за токеном: он уже лежит на сервере.
if [[ -z "$AGENT_TOKEN" && -f "$ENV_FILE" ]]; then
  AGENT_TOKEN="$(sed -n 's/^AGENT_TOKEN=//p' "$ENV_FILE" | tail -1)"
  AGENT_PORT="$(sed -n 's/^AGENT_PORT=//p' "$ENV_FILE" | tail -1)"
  AGENT_PORT="${AGENT_PORT:-8443}"
  [[ -n "$AGENT_TOKEN" ]] && echo "==> Обновление: токен взят из ${ENV_FILE}"
fi

if [[ -z "$AGENT_TOKEN" ]]; then
  echo "Не задан AGENT_TOKEN (возьмите его в панели при добавлении сервера)" >&2
  exit 1
fi
if [[ -z "$PANEL_URL" ]]; then
  echo "Не задан PANEL_URL (адрес вашей панели)" >&2
  exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "Запускать нужно от root" >&2
  exit 1
fi

echo "==> Ставим зависимости"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl unzip ca-certificates python3 python3-venv >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q curl unzip ca-certificates python3 >/dev/null
else
  echo "Неизвестный дистрибутив: поставьте curl, unzip и python3 вручную" >&2
  exit 1
fi

if [[ -x /usr/local/bin/xray && "${XRAY_FORCE:-0}" != "1" ]]; then
  echo "==> Xray уже установлен ($(/usr/local/bin/xray version 2>/dev/null | head -1))"
  echo "    пропускаем скачивание; XRAY_FORCE=1 — переустановить"
  SKIP_XRAY=1
else
  SKIP_XRAY=0
fi

echo "==> Определяем архитектуру"
case "$(uname -m)" in
  x86_64|amd64)  XRAY_ASSET="Xray-linux-64.zip" ;;
  aarch64|arm64) XRAY_ASSET="Xray-linux-arm64-v8a.zip" ;;
  armv7l)        XRAY_ASSET="Xray-linux-arm32-v7a.zip" ;;
  *) echo "Неподдерживаемая архитектура: $(uname -m)" >&2; exit 1 ;;
esac

if [[ "$SKIP_XRAY" == "0" ]]; then
echo "==> Ставим Xray-core ($XRAY_ASSET)"
if [[ "$XRAY_VERSION" == "latest" ]]; then
  XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/${XRAY_ASSET}"
else
  XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_ASSET}"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL "$XRAY_URL" -o "$TMP_DIR/xray.zip"
unzip -oq "$TMP_DIR/xray.zip" -d "$TMP_DIR/xray"
install -m 755 "$TMP_DIR/xray/xray" /usr/local/bin/xray
mkdir -p /usr/local/share/xray /usr/local/etc/xray
for asset in geoip.dat geosite.dat; do
  [[ -f "$TMP_DIR/xray/$asset" ]] && install -m 644 "$TMP_DIR/xray/$asset" /usr/local/share/xray/
done
else
  mkdir -p /usr/local/share/xray /usr/local/etc/xray
fi

echo "==> Ставим агента в $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
# Скачиваем рядом и только потом подменяем: если панель ответит 502 (например,
# её как раз перезапускают), рабочий агент останется на месте.
NEW_AGENT="$INSTALL_DIR/agent.py.new"
if ! curl -fsSL "${PANEL_URL%/}/install/agent.py" -o "$NEW_AGENT"; then
  rm -f "$NEW_AGENT"
  echo "Не удалось скачать agent.py с ${PANEL_URL%/}" >&2
  echo "Проверьте, что панель отвечает: curl -I ${PANEL_URL%/}/healthz" >&2
  [[ -f "$INSTALL_DIR/agent.py" ]] && echo "Прежний агент не тронут, он продолжает работать" >&2
  exit 1
fi
if ! grep -q "class XrayProcess" "$NEW_AGENT"; then
  rm -f "$NEW_AGENT"
  echo "По адресу ${PANEL_URL%/}/install/agent.py лежит не агент (похоже на страницу ошибки)" >&2
  exit 1
fi
mv "$NEW_AGENT" "$INSTALL_DIR/agent.py"

if [[ ! -d "$INSTALL_DIR/venv" ]]; then
  python3 -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
# Диапазоны, а не точные версии: на свежих Ubuntu системный Python новее,
# и жёсткий пин отправил бы pip собирать pydantic-core из исходников.
"$INSTALL_DIR/venv/bin/pip" install --quiet "fastapi>=0.115.6,<1" "uvicorn>=0.34.0,<1"

cat > "$INSTALL_DIR/agent.env" <<EOF
AGENT_TOKEN=${AGENT_TOKEN}
AGENT_PORT=${AGENT_PORT}
XRAY_BIN=/usr/local/bin/xray
XRAY_CONFIG=/usr/local/etc/xray/config.json
XRAY_ASSETS=/usr/local/share/xray
EOF
chmod 600 "$INSTALL_DIR/agent.env"

# Пустой конфиг, чтобы агент стартовал до первой синхронизации с панелью.
if [[ ! -f /usr/local/etc/xray/config.json ]]; then
  cat > /usr/local/etc/xray/config.json <<'EOF'
{
  "log": {"loglevel": "warning"},
  "inbounds": [],
  "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}]
}
EOF
fi

echo "==> Настраиваем systemd"
cat > /etc/systemd/system/vpn-agent.service <<EOF
[Unit]
Description=VPN Panel Node Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=${INSTALL_DIR}/agent.env
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/agent.py
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpn-agent >/dev/null 2>&1 || true
# Именно restart, а не enable --now: при обновлении уже запущенный сервис
# от --now не перезапустится и продолжит работать на прежнем agent.py.
systemctl restart vpn-agent
sleep 2
systemctl --no-pager --lines=10 status vpn-agent || true

if [[ "$IS_UPDATE" == "1" ]]; then
  cat <<EOF

==> Агент обновлён и перезапущен. Порт ${AGENT_PORT}, токен не менялся.
Xray: $(/usr/local/bin/xray version 2>/dev/null | head -1)
Логи агента:  journalctl -u vpn-agent -f
EOF
else
  cat <<EOF

==> Готово.
Агент слушает порт ${AGENT_PORT}.

ВАЖНО: закройте этот порт для всех, кроме адреса панели, например:
  ufw allow from <IP панели> to any port ${AGENT_PORT} proto tcp
  ufw deny ${AGENT_PORT}/tcp

Логи агента:  journalctl -u vpn-agent -f
EOF
fi
