#!/usr/bin/env bash
# Раздача ноды через передний сервер («сервер белых списков»).
#
# Запускать НА ПЕРЕДНЕМ СЕРВЕРЕ — том, чей адрес вы даёте клиентам.
#
#   bash setup_front.sh --node 78.17.173.142:443 --sni www.lovelive-anime.jp
#
# Зачем. Адрес ноды у провайдера может не проходить, а адрес другого сервера —
# проходить. Тогда клиентам дают адрес переднего сервера, а он передаёт
# соединение ноде.
#
# Почему не обычный прокси. REALITY — это и есть TLS: клиент ждёт рукопожатие
# от самой ноды. Обычный proxy_pass внутри http {} отвечает клиенту своим
# сертификатом, и до ноды соединение не доходит. Нужен stream с ssl_preread:
# nginx смотрит только имя домена в первом пакете и отдаёт поток байт в байт.
#
# Что делает скрипт:
#   * ставит nginx и модуль stream, если их нет;
#   * забирает порт 443 под stream, а http-серверы (панель, сайты) переносит
#     на 127.0.0.1:8443 — и добавляет их имена в правила, чтобы они работали
#     как раньше;
#   * добавляет правило «маскировочный домен → нода»;
#   * проверяет конфиг и откатывается целиком, если nginx его не принял.
#
# Запускать можно сколько угодно раз: каждый запуск добавляет одно правило.
#
# Ключи:
#   --node <адрес:порт>  куда отдавать поток (адрес ноды и порт подключения)
#   --sni <домен>        маскировочный домен подключения: serverNames у
#                        REALITY, он же sni= в ссылке. По нему nginx и
#                        различает ноды — у каждой должен быть свой
#   --udp <порт>         вдобавок пробросить UDP-порт (Hysteria2). ssl_preread
#                        к UDP неприменим, поэтому это простая пересылка:
#                        порт на переднем сервере отдаётся одной ноде целиком
#   --remove             удалить правило для этого --sni
#   --status             показать текущие правила и ничего не менять

set -euo pipefail

NGINX_CONF="/etc/nginx/nginx.conf"
STREAM_DIR="/etc/nginx/stream.d"
ROUTES_DIR="/etc/nginx/stream-routes"
FRONT_CONF="$STREAM_DIR/vpn-front.conf"
# Куда уезжают http-серверы, освобождая 443 под stream.
LOCAL_HTTPS="127.0.0.1:8443"

NODE=""
SNI=""
UDP_PORT=""
REMOVE=0
STATUS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) NODE="$2"; shift 2 ;;
    --sni) SNI="$2"; shift 2 ;;
    --udp) UDP_PORT="$2"; shift 2 ;;
    --remove) REMOVE=1; shift ;;
    --status) STATUS=1; shift ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "Неизвестный ключ: $1" >&2; exit 1 ;;
  esac
done

route_file() {
  # Имя файла правила: точки в имени домена мешают читать вывод ls.
  printf '%s/%s.map' "$ROUTES_DIR" "${1//[^A-Za-z0-9_.-]/_}"
}

show_status() {
  echo
  echo "Правила на этом сервере (домен → куда идёт поток):"
  if compgen -G "$ROUTES_DIR/*.map" >/dev/null; then
    sed -e 's/;$//' -e 's/^/  /' "$ROUTES_DIR"/*.map
  else
    echo "  пусто — ни одного правила нет"
  fi
  echo
  echo "Кто слушает 443:"
  ss -lntup 2>/dev/null | grep -E ':443\s' | sed 's/^/  /' || echo "  никто"
  echo
}

if [[ "$STATUS" == "1" ]]; then
  show_status
  exit 0
fi

if [[ -z "$SNI" ]] || { [[ -z "$NODE" ]] && [[ "$REMOVE" == "0" ]]; }; then
  cat >&2 <<'EOF'
Использование:
  bash setup_front.sh --node <адрес ноды:порт> --sni <маскировочный домен>
  bash setup_front.sh --sni <маскировочный домен> --remove
  bash setup_front.sh --status

Адрес ноды и порт — те же, что в панели у сервера и подключения.
Маскировочный домен — значение sni= из ссылки подписки.
EOF
  exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "Запускать нужно от root" >&2
  exit 1
fi
if [[ "$REMOVE" == "0" ]] && [[ ! "$NODE" =~ ^[A-Za-z0-9._-]+:[0-9]+$ ]]; then
  echo "--node нужно указывать как адрес:порт, например 78.17.173.142:443" >&2
  exit 1
fi

# --- Снимок конфига: откатываться будет чем ---------------------------------

BACKUP="/etc/nginx.backup.$(date +%Y%m%d-%H%M%S)"
echo "==> Снимок текущего конфига: $BACKUP"
cp -a /etc/nginx "$BACKUP"

WAS_ACTIVE=0
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
  WAS_ACTIVE=1
fi

rollback() {
  echo "==> Откатываю конфиг из $BACKUP"
  rm -rf /etc/nginx
  cp -a "$BACKUP" /etc/nginx
  nginx -t >/dev/null 2>&1 && { systemctl reload nginx >/dev/null 2>&1 || true; }
}

# --- Пакеты ----------------------------------------------------------------

if ! command -v nginx >/dev/null 2>&1; then
  echo "==> Ставлю nginx"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx >/dev/null
fi

if ! nginx -V 2>&1 | grep -q stream_ssl_preread; then
  echo "Этот nginx собран без ssl_preread — пробросить REALITY через него нельзя." >&2
  echo "Поставьте nginx из репозитория дистрибутива и запустите скрипт снова." >&2
  exit 1
fi

# В сборках Debian/Ubuntu stream — отдельный модуль, без него nginx не поймёт
# ни одной директивы из конфига ниже.
if nginx -V 2>&1 | grep -q -- "--with-stream=dynamic" \
   && ! ls /etc/nginx/modules-enabled/*stream* >/dev/null 2>&1; then
  echo "==> Ставлю модуль stream"
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq libnginx-mod-stream >/dev/null || {
    echo "Не удалось поставить libnginx-mod-stream — поставьте его вручную." >&2
    exit 1
  }
fi

mkdir -p "$STREAM_DIR" "$ROUTES_DIR"

# --- Переносим http-серверы с 443 ------------------------------------------

# Порт 443 нужен целиком под stream, поэтому всё, что слушало его по http,
# уезжает на локальный адрес. Имена таких серверов попадают в правила — иначе
# панель и сайты перестанут открываться.
moved_names=()
moved_files=()
for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
  [[ -e "$conf" ]] || continue
  grep -qE '^\s*listen\s+(\[::\]:)?443\s' "$conf" || continue

  echo "==> Переношу с 443 на $LOCAL_HTTPS: $conf"
  moved_files+=("$conf")
  # IPv4 остаётся, но уже на localhost; IPv6-строку убираем — снаружи слушает
  # stream, а к нему nginx ходит по IPv4.
  sed -i -E "s|^([[:space:]]*)listen[[:space:]]+(0\.0\.0\.0:)?443([[:space:];])|\1listen ${LOCAL_HTTPS}\3|" "$conf"
  sed -i -E "s|^([[:space:]]*)listen[[:space:]]+\[::\]:443|\1# перенесено в stream: listen [::]:443|" "$conf"

  while read -r line; do
    for name in $line; do
      [[ "$name" == "server_name" || "$name" == ";" || "$name" == "_" ]] && continue
      moved_names+=("${name%;}")
    done
  done < <(grep -hE '^\s*server_name\s' "$conf" || true)
done

for name in "${moved_names[@]:-}"; do
  [[ -z "$name" ]] && continue
  printf '%s %s;\n' "$name" "$LOCAL_HTTPS" > "$(route_file "$name")"
  echo "    правило: $name → $LOCAL_HTTPS (как было)"
done

# --- Правило для ноды -------------------------------------------------------

if [[ "$REMOVE" == "1" ]]; then
  rm -f "$(route_file "$SNI")"
  echo "==> Правило для $SNI удалено"
else
  printf '%s %s;\n' "$SNI" "$NODE" > "$(route_file "$SNI")"
  echo "==> Правило: $SNI → $NODE"
fi

# --- Сам stream -------------------------------------------------------------

# На серверах с выключенным IPv6 директива listen [::] роняет nginx целиком,
# поэтому добавляем её только когда стек действительно есть.
LISTEN6=""
LISTEN6_UDP=""
if [[ -f /proc/net/if_inet6 ]]; then
  LISTEN6="
    listen [::]:443 reuseport;"
  LISTEN6_UDP="
        listen [::]:${UDP_PORT} udp;"
fi

UDP_SERVER=""
if [[ -n "$UDP_PORT" ]]; then
  UDP_SERVER="
    # Hysteria2 и прочий QUIC: имя домена в UDP не подсмотреть, поэтому порт
    # целиком отдан одной ноде.
    server {
        listen ${UDP_PORT} udp;${LISTEN6_UDP}
        proxy_pass ${NODE%:*}:${UDP_PORT};
        proxy_timeout 5m;
    }"
fi

cat > "$FRONT_CONF" <<EOF
# Создано scripts/setup_front.sh — правила лежат в ${ROUTES_DIR}/
#
# ssl_preread читает имя домена из первого пакета и по нему выбирает,
# куда отдать поток. Дальше nginx в него не заглядывает: TLS остаётся
# между клиентом и нодой, а именно этого и требует REALITY.
map \$ssl_preread_server_name \$vpn_front_upstream {
    include ${ROUTES_DIR}/*.map;
    default ${LOCAL_HTTPS};
}

server {
    listen 443 reuseport;${LISTEN6}
    ssl_preread on;
    proxy_pass \$vpn_front_upstream;
    # Рукопожатие REALITY идёт к маскировочному домену и бывает небыстрым.
    proxy_connect_timeout 10s;
    proxy_timeout 10m;
}
${UDP_SERVER}
EOF

# Подключаем каталог stream.d, если он ещё не подключён. Блок stream должен
# лежать рядом с http {}, а не внутри: sites-enabled подключается внутри
# http {}, и правило, положенное туда, nginx не примет.
if ! grep -qE '^\s*stream\s*\{' "$NGINX_CONF"; then
  echo "==> Подключаю $STREAM_DIR в $NGINX_CONF"
  printf '\nstream {\n    include %s/*.conf;\n}\n' "$STREAM_DIR" >> "$NGINX_CONF"
elif ! grep -q "$STREAM_DIR" "$NGINX_CONF"; then
  echo
  echo "В $NGINX_CONF уже есть свой блок stream {}. Добавьте в него строку:"
  echo "    include $STREAM_DIR/*.conf;"
  echo "и запустите скрипт снова."
  rollback
  exit 1
fi

# --- Проверка ---------------------------------------------------------------

echo "==> Проверяю конфиг"
if ! nginx -t; then
  echo
  echo "Nginx конфиг не принял — ничего не изменено, откатываюсь." >&2
  rollback
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload nginx >/dev/null 2>&1 || systemctl start nginx >/dev/null 2>&1 || true
  sleep 1
  # Конфиг может быть верным, а порт — занятым: тогда nginx падает уже после
  # проверки, и вместе с ним уходит панель. Это тоже повод откатиться.
  if [[ "$WAS_ACTIVE" == "1" ]] && ! systemctl is-active --quiet nginx 2>/dev/null; then
    echo "Nginx не поднялся — откатываюсь." >&2
    systemctl status nginx --no-pager -l 2>&1 | head -20 >&2
    rollback
    exit 1
  fi
else
  nginx -s reload >/dev/null 2>&1 || true
fi

if command -v ufw >/dev/null 2>&1; then
  ufw allow 443/tcp >/dev/null 2>&1 || true
  [[ -n "$UDP_PORT" ]] && ufw allow "${UDP_PORT}/udp" >/dev/null 2>&1 || true
fi

# --- Что получилось ---------------------------------------------------------

CHECK="не проверено"
if [[ "$REMOVE" == "0" ]] && command -v openssl >/dev/null 2>&1; then
  sleep 1
  # REALITY на чужое рукопожатие отвечает настоящим сертификатом
  # маскировочного домена. Его имя в ответе и значит, что поток дошёл до ноды.
  SUBJECT="$(echo | timeout 15 openssl s_client -connect "127.0.0.1:443" \
    -servername "$SNI" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)"
  if [[ "$SUBJECT" == *"$SNI"* ]]; then
    CHECK="поток доходит до ноды (сертификат $SNI)"
  elif [[ -n "$SUBJECT" ]]; then
    CHECK="отвечает не нода, а ${SUBJECT#subject=} — проверьте адрес и порт ноды"
  else
    CHECK="ответа нет — похоже, нода недоступна с этого сервера"
  fi
fi

show_status

cat <<EOF
======================================================================
Проверка: ${CHECK}

Дальше — в панели, раздел «Подписка» → «Настроить» у нужной строки:
  Адрес = адрес ЭТОГО сервера, остальное не трогать.
  SNI, порт и ключи принадлежат ноде и меняться не должны.

О чём стоит знать:
  * счётчик устройств для этой строки перестанет работать: ноде все
    подключения приходят с одного адреса — этого сервера;
  * у каждой ноды должен быть свой маскировочный домен: nginx различает
    их только по нему;
  * если на ноде файрвол закрывает порт, откройте его для адреса этого
    сервера.

Правила:  $ROUTES_DIR/
Конфиг:   $FRONT_CONF
Откат:    rm -rf /etc/nginx && cp -a $BACKUP /etc/nginx && systemctl reload nginx
======================================================================
EOF
