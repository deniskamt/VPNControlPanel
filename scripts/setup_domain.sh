#!/usr/bin/env bash
# Перевод панели на домен и HTTPS: nginx, сертификат Let's Encrypt,
# правка .env и systemd-юнита.
#
#   bash scripts/setup_domain.sh vixar.fun
#   bash scripts/setup_domain.sh vixar.fun --sub nexlovpn.online --email me@example.com
#
# Что делает:
#   * ставит nginx и certbot;
#   * настраивает проксирование домена на панель;
#   * получает сертификат и включает автопродление;
#   * прописывает https-адреса в .env и перезапускает панель;
#   * закрывает прямой порт панели — снаружи остаётся только nginx.
#
# Ключи:
#   --sub <домен>   домен для ссылок подписок (по умолчанию тот же)
#   --email <адрес> адрес для Let's Encrypt (иначе выпуск без него)
#   --no-cert       только nginx, без сертификата (для проверки)
#   --staging       тестовый центр сертификации Let's Encrypt

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$INSTALL_DIR/.env"
UNIT_FILE="/etc/systemd/system/vpn-panel.service"

DOMAIN="${1:-}"
shift || true
SUB_DOMAIN=""
EMAIL=""
NO_CERT=0
STAGING=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sub) SUB_DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --no-cert) NO_CERT=1; shift ;;
    --staging) STAGING=1; shift ;;
    *) echo "Неизвестный ключ: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "Использование: bash scripts/setup_domain.sh <домен> [--sub <домен подписок>] [--email <адрес>]" >&2
  exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "Запускать нужно от root" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Не вижу $ENV_FILE — сначала установите панель" >&2
  exit 1
fi

SUB_DOMAIN="${SUB_DOMAIN:-$DOMAIN}"
APP_PORT="$(sed -n 's/.*--port \([0-9]*\).*/\1/p' "$UNIT_FILE" 2>/dev/null | head -1)"
APP_PORT="${APP_PORT:-8000}"

echo "==> Домен панели:    $DOMAIN"
echo "==> Домен подписок:  $SUB_DOMAIN"
echo "==> Панель работает на порту $APP_PORT"

# --- Проверки до изменений -------------------------------------------------

echo "==> Проверяем, свободен ли порт 443"
# Не полагаемся на ss: на минимальных образах его может не быть, а тихо
# пропущенная проверка тут дороже — она защищает от конфликта с VPN.
port_busy() {
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | grep -qE "(^|\s)(0\.0\.0\.0|\[::\]|\*|127\.0\.0\.1):$1\s" && return 0
  fi
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && exec 3>&- && return 0
  return 1
}

if port_busy 443; then
  OWNER="$(ss -lntp 2>/dev/null | grep -E ':443\s' | head -1 || echo 'не удалось определить процесс')"
  cat >&2 <<EOF

Порт 443 уже занят:
  $OWNER

Скорее всего это Xray с подключением на 443. Панель и VPN не могут слушать
один порт одновременно. Варианты:

  1. Перенести VPN на другой порт: в панели «Подключения» → «Настроить» →
     порт, например 8443. Клиенты получат новые ссылки автоматически.
  2. Оставить 443 за VPN, а панель открыть на другом порту — тогда этот
     скрипт не нужен, настройте nginx вручную (docs/DEPLOY.md).

Скрипт остановлен, ничего не изменено.
EOF
  exit 1
fi

echo "==> Проверяем, что домен указывает на этот сервер"
SERVER_IP="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
DOMAIN_IP="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}')"
if [[ -z "$DOMAIN_IP" ]]; then
  echo "  ВНИМАНИЕ: $DOMAIN пока никуда не резолвится — сертификат не выпустится."
elif [[ "$DOMAIN_IP" != "$SERVER_IP" ]]; then
  echo "  ВНИМАНИЕ: $DOMAIN указывает на $DOMAIN_IP, а сервер — $SERVER_IP."
  echo "  Если домен за Cloudflare с оранжевым облаком, для выпуска сертификата"
  echo "  переключите запись в «DNS only» (серое облако)."
else
  echo "  $DOMAIN → $DOMAIN_IP, совпадает с адресом сервера"
fi

# --- Nginx -----------------------------------------------------------------

echo "==> Ставим nginx и certbot"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx certbot python3-certbot-nginx >/dev/null

SERVER_NAMES="$DOMAIN"
[[ "$SUB_DOMAIN" != "$DOMAIN" ]] && SERVER_NAMES="$DOMAIN $SUB_DOMAIN"

# На серверах с выключенным IPv6 директива listen [::] роняет nginx целиком,
# поэтому добавляем её только когда стек действительно есть.
LISTEN6=""
if [[ -f /proc/net/if_inet6 ]]; then
  LISTEN6="    listen [::]:80;"
fi

echo "==> Настраиваем nginx"
cat > /etc/nginx/sites-available/vpn-panel <<EOF
server {
    listen 80;
${LISTEN6}
    server_name ${SERVER_NAMES};

    # Ссылки подписок могут быть длинными, а клиенты — медленными.
    client_max_body_size 4m;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        # По этому заголовку панель понимает, что работает по HTTPS,
        # и ставит cookie сессии с флагом Secure.
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/vpn-panel /etc/nginx/sites-enabled/vpn-panel
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx 2>/dev/null || systemctl start nginx 2>/dev/null || service nginx reload || true

echo "==> Открываем порты 80 и 443"
if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
fi

# --- Сертификат ------------------------------------------------------------

SCHEME="http"
if [[ "$NO_CERT" == "1" ]]; then
  echo "==> Сертификат пропущен (--no-cert)"
else
  echo "==> Получаем сертификат Let's Encrypt"
  CERTBOT_ARGS=(--nginx --non-interactive --agree-tos --redirect -d "$DOMAIN")
  [[ "$SUB_DOMAIN" != "$DOMAIN" ]] && CERTBOT_ARGS+=(-d "$SUB_DOMAIN")
  if [[ -n "$EMAIL" ]]; then
    CERTBOT_ARGS+=(-m "$EMAIL")
  else
    CERTBOT_ARGS+=(--register-unsafely-without-email)
  fi
  [[ "$STAGING" == "1" ]] && CERTBOT_ARGS+=(--staging)

  if certbot "${CERTBOT_ARGS[@]}"; then
    SCHEME="https"
    echo "  сертификат получен, автопродление настроено certbot'ом"
  else
    cat >&2 <<EOF

Сертификат получить не удалось. Частые причины:
  * запись домена в Cloudflare стоит на «Proxied» (оранжевое облако) —
    переключите на «DNS only» и повторите;
  * порт 80 закрыт файрволом или занят;
  * домен ещё не разошёлся по DNS — подождите и запустите скрипт снова.

Nginx уже настроен, панель доступна по http://${DOMAIN}
EOF
  fi
fi

# --- Настройки панели ------------------------------------------------------

echo "==> Прописываем адреса в .env"
cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%s)"
set_env() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}
set_env PANEL_URL "${SCHEME}://${DOMAIN}"
set_env SUBSCRIPTION_BASE_URL "${SCHEME}://${SUB_DOMAIN}"

# --- Панель за nginx -------------------------------------------------------

if [[ -f "$UNIT_FILE" ]] && grep -q -- "--host 0.0.0.0" "$UNIT_FILE"; then
  echo "==> Убираем панель с внешнего интерфейса — наружу её пускает nginx"
  sed -i "s|--host 0\.0\.0\.0|--host 127.0.0.1|" "$UNIT_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "${APP_PORT}/tcp" >/dev/null 2>&1 || true
  fi
fi

systemctl restart vpn-panel 2>/dev/null || echo "  перезапустите панель вручную"
sleep 3

echo "==> Проверяем"
# Без -f: на ошибочном ответе curl вернул бы ненулевой код, и к номеру
# статуса приклеился бы запасной «000».
CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
  "${SCHEME}://${DOMAIN}/healthz" 2>/dev/null || true)"
CODE="${CODE:-000}"

cat <<EOF

======================================================================
Панель:   ${SCHEME}://${DOMAIN}          (проверка /healthz: ${CODE})
Подписки: ${SCHEME}://${SUB_DOMAIN}/<путь>/<token>

Что стоит сделать дальше:
  * если домен за Cloudflare, вернуть оранжевое облако можно, но режим SSL
    должен быть Full (strict) — иначе будет цикл редиректов;
  * адрес серверов для клиентов лучше оставить по IP или завести отдельную
    запись без проксирования: VPN-трафик через Cloudflare не ходит;
  * старые ссылки подписок останутся рабочими, только если домен подписок
    не менялся.

Логи:     journalctl -u vpn-panel -f
Nginx:    nginx -t && systemctl reload nginx
======================================================================
EOF
