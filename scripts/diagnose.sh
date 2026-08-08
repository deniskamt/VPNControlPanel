#!/usr/bin/env bash
# Проверка установки: что запущено, что слушает, куда смотрит домен и
# доходит ли до панели снаружи. Секреты не печатаются.
#
#   bash scripts/diagnose.sh
#
# Полезно, когда «локально работает, а из браузера нет»: почти всегда это
# либо закрытый порт, либо DNS, либо проксирование Cloudflare.

set -uo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$INSTALL_DIR/.env"

env_value() {
  [[ -f "$ENV_FILE" ]] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$1"; }
info() { printf '    %s\n' "$1"; }

PANEL_URL="$(env_value PANEL_URL)"
DOMAIN="${PANEL_URL#*://}"
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN%%/*}"
APP_PORT="$(sed -n 's/.*--port \([0-9]*\).*/\1/p' /etc/systemd/system/vpn-panel.service 2>/dev/null | head -1)"
APP_PORT="${APP_PORT:-8000}"

say "Панель"
echo "  адрес в настройках: ${PANEL_URL:-не задан}"
if systemctl is-active --quiet vpn-panel 2>/dev/null; then
  ok "сервис vpn-panel запущен"
else
  bad "сервис vpn-panel не запущен — journalctl -u vpn-panel -n 30"
fi
CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:${APP_PORT}/healthz" 2>/dev/null)"
if [[ "$CODE" == "200" ]]; then
  ok "панель отвечает на 127.0.0.1:${APP_PORT}"
else
  bad "панель не отвечает на 127.0.0.1:${APP_PORT} (код ${CODE:-нет ответа})"
fi

say "Что слушает порты"
if command -v ss >/dev/null 2>&1; then
  ss -lntp 2>/dev/null | awk 'NR==1 || /:(80|443|'"${APP_PORT}"')\s/ {print "  " $0}'
else
  info "утилита ss не установлена: apt install -y iproute2"
fi

say "Nginx"
if command -v nginx >/dev/null 2>&1; then
  if nginx -t >/dev/null 2>&1; then ok "конфиг корректен"; else bad "ошибка конфига:"; nginx -t 2>&1 | sed 's/^/    /'; fi
  if systemctl is-active --quiet nginx 2>/dev/null; then ok "nginx запущен"; else bad "nginx не запущен"; fi
  if grep -rqs "listen.*443" /etc/nginx/sites-enabled/ 2>/dev/null; then
    ok "есть слушатель на 443"
  else
    bad "в конфигах нет listen 443 — сертификат не подключён"
  fi
else
  bad "nginx не установлен"
fi

say "Сертификат"
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
if [[ -f "$CERT" ]]; then
  ok "сертификат для ${DOMAIN} есть"
  info "$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | sed 's/notAfter=/действует до /')"
else
  bad "сертификата для ${DOMAIN} нет (${CERT})"
fi

say "Панель через nginx, локально"
LOCAL_HTTPS="$(curl -sSk -o /dev/null -w '%{http_code}' --max-time 8 \
  --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/healthz" 2>/dev/null)"
if [[ "$LOCAL_HTTPS" == "200" ]]; then
  ok "https на самом сервере работает (код 200)"
  info "значит панель, nginx и сертификат в порядке — проблема снаружи"
else
  bad "https на самом сервере отвечает кодом ${LOCAL_HTTPS:-нет ответа}"
fi

say "DNS"
SERVER_IP="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
DOMAIN_IP="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}')"
PROXIED=0
echo "  IP сервера: ${SERVER_IP:-не определён}"
echo "  ${DOMAIN} → ${DOMAIN_IP:-не резолвится}"
if [[ -z "$DOMAIN_IP" ]]; then
  bad "домен никуда не указывает — проверьте A-запись"
elif [[ "$DOMAIN_IP" == "$SERVER_IP" ]]; then
  ok "домен указывает прямо на сервер"
else
  case "$DOMAIN_IP" in
    104.*|172.6[4-9].*|172.7[0-1].*|173.245.*|188.114.*|190.93.*|197.234.*|198.41.*|162.15[89].*|141.101.*|108.162.*|103.2[12].*)
      PROXIED=1
      bad "домен проксируется Cloudflare (${DOMAIN_IP}), а не смотрит на сервер"
      info "в браузере это выглядит как ошибка 5xx или бесконечный редирект"
      info "проверьте: режим SSL/TLS должен быть Full (strict), не Flexible"
      info "или переключите запись в DNS only (серое облако)"
      ;;
    *)
      bad "домен указывает на ${DOMAIN_IP}, а сервер — ${SERVER_IP}"
      ;;
  esac
fi

say "Cloudflare: проверка на петлю редиректов"
REDIRECT="$(curl -sSI -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 8 \
  --resolve "${DOMAIN}:80:127.0.0.1" "http://${DOMAIN}/" 2>/dev/null)"
echo "  http на сервере отвечает: ${REDIRECT:-нет ответа}"
if [[ "$REDIRECT" == 30[0-9]*https://* && "$PROXIED" == "1" ]]; then
  bad "сервер перенаправляет http → https, а домен идёт через Cloudflare"
  info "Если в Cloudflare режим SSL/TLS = Flexible, он ходит к серверу по http,"
  info "получает этот редирект и отдаёт его браузеру — и так по кругу."
  info "Браузер покажет ERR_TOO_MANY_REDIRECTS."
  info "Лечится в Cloudflare: SSL/TLS → Overview → Full (strict)."
elif [[ "$PROXIED" == "1" ]]; then
  info "домен проксируется; убедитесь, что режим SSL/TLS — Full (strict)"
else
  ok "домен не проксируется, петли редиректов быть не может"
fi

say "Файрвол"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw status 2>/dev/null | grep -E "80|443|${APP_PORT}" | sed 's/^/  /'
  ufw status 2>/dev/null | grep -q "443" || bad "порт 443 в ufw не открыт: ufw allow 443/tcp"
else
  info "ufw не активен — правила могут быть в iptables или в панели хостера"
  iptables -L INPUT -n 2>/dev/null | head -5 | sed 's/^/  /'
fi
info "Если локально всё зелёное, а снаружи не открывается — почти всегда"
info "порт 443 закрыт файрволом хостера (в панели VPS, а не в системе)."

say "Агент на этом сервере"
if systemctl is-active --quiet vpn-agent 2>/dev/null; then
  ok "сервис vpn-agent запущен"
  AGENT_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:8443/health 2>/dev/null)"
  [[ "$AGENT_CODE" == "401" ]] && ok "агент отвечает на 127.0.0.1:8443 (401 без токена — это норма)" \
    || info "ответ агента: ${AGENT_CODE:-нет ответа}"
else
  info "vpn-agent не установлен — это нормально, если VPN на другом сервере"
fi

say "Проверка снаружи"
echo "  Выполните со своего компьютера:"
echo "    curl -v https://${DOMAIN}/healthz"
echo "  PowerShell:"
echo "    Test-NetConnection ${DOMAIN} -Port 443"
echo
