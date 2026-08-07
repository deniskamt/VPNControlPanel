#!/usr/bin/env bash
# Установка агента панели на VPN-сервер: Xray-core + агент + systemd-сервис.
#
#   AGENT_TOKEN=<токен из панели> PANEL_URL=https://panel.example.com bash install_agent.sh
#
# Переменные:
#   AGENT_TOKEN  (обяз.) — токен, который панель показывает в форме сервера
#   PANEL_URL    (обяз.) — адрес панели, откуда скачивается agent.py
#   AGENT_PORT   — порт агента, по умолчанию 8443
#   XRAY_VERSION — версия ядра, по умолчанию последняя

set -euo pipefail

AGENT_TOKEN="${AGENT_TOKEN:-}"
PANEL_URL="${PANEL_URL:-}"
AGENT_PORT="${AGENT_PORT:-8443}"
XRAY_VERSION="${XRAY_VERSION:-latest}"
INSTALL_DIR="/opt/vpn-agent"

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

echo "==> Определяем архитектуру"
case "$(uname -m)" in
  x86_64|amd64)  XRAY_ASSET="Xray-linux-64.zip" ;;
  aarch64|arm64) XRAY_ASSET="Xray-linux-arm64-v8a.zip" ;;
  armv7l)        XRAY_ASSET="Xray-linux-arm32-v7a.zip" ;;
  *) echo "Неподдерживаемая архитектура: $(uname -m)" >&2; exit 1 ;;
esac

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

echo "==> Ставим агента в $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
curl -fsSL "${PANEL_URL%/}/install/agent.py" -o "$INSTALL_DIR/agent.py"

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
systemctl enable --now vpn-agent
sleep 2
systemctl --no-pager --lines=10 status vpn-agent || true

cat <<EOF

==> Готово.
Агент слушает порт ${AGENT_PORT}.

ВАЖНО: закройте этот порт для всех, кроме адреса панели, например:
  ufw allow from <IP панели> to any port ${AGENT_PORT} proto tcp
  ufw deny ${AGENT_PORT}/tcp

Логи агента:  journalctl -u vpn-agent -f
EOF
