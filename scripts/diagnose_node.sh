#!/usr/bin/env bash
# Разбор «xray упал» на VPN-сервере: показывает, что именно не нравится ядру.
#
#   curl -fsSL https://panel.example.com/install/diagnose_node.sh -o diagnose_node.sh
#   bash diagnose_node.sh
#
# Скрипт только смотрит и ничего не меняет.

INSTALL_DIR="/opt/vpn-agent"
ENV_FILE="$INSTALL_DIR/agent.env"
XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
CONFIG="${XRAY_CONFIG:-/usr/local/etc/xray/config.json}"
REJECTED="${CONFIG%.json}.rejected.json"
STDOUT_LOG="${XRAY_STDOUT_LOG:-/usr/local/etc/xray/xray-stdout.log}"

ok()   { echo "  [ ok ] $*"; }
bad()  { echo "  [ !! ] $*"; }
info() { echo "  [ .. ] $*"; }

echo "== Агент =="
if [[ -f "$ENV_FILE" ]]; then
  ok "установлен в $INSTALL_DIR"
  version="$(sed -n 's/^AGENT_VERSION *= *\([0-9]\+\).*/\1/p' "$INSTALL_DIR/agent.py" 2>/dev/null | head -1)"
  if [[ -n "$version" ]]; then
    ok "версия агента: $version"
  else
    bad "версия не читается — агент старый, обновите его (см. панель → «Установка»)"
  fi
else
  bad "агента здесь нет ($ENV_FILE отсутствует)"
  bad "если это сервер панели — диагностику нужно запускать на VPN-сервере"
fi

if command -v systemctl >/dev/null 2>&1; then
  state="$(systemctl is-active vpn-agent 2>/dev/null)"
  [[ "$state" == "active" ]] && ok "сервис vpn-agent: active" || bad "сервис vpn-agent: ${state:-не найден}"
fi

echo
echo "== Ядро Xray =="
if [[ -x "$XRAY_BIN" ]]; then
  ok "$("$XRAY_BIN" version 2>&1 | head -1)"
else
  bad "нет ядра по пути $XRAY_BIN"
fi

if pgrep -f "$XRAY_BIN run" >/dev/null 2>&1; then
  ok "процесс xray запущен"
else
  bad "процесс xray НЕ запущен — это и есть «xray упал»"
fi

echo
echo "== Что сказало ядро при последнем запуске =="
if [[ -s "$STDOUT_LOG" ]]; then
  grep -v -e '\[Info\]' -e '\[Debug\]' -e 'Penetrates Everything' -e 'A unified platform' \
    "$STDOUT_LOG" | tail -15
else
  info "$STDOUT_LOG пуст или отсутствует (старый агент вывод ядра не сохранял)"
fi

echo
echo "== Проверка конфигов ядром =="
for file in "$CONFIG" "$REJECTED"; do
  [[ -f "$file" ]] || continue
  echo "-- $file"
  if [[ -x "$XRAY_BIN" ]]; then
    if out="$("$XRAY_BIN" run -test -config "$file" 2>&1)"; then
      ok "конфиг корректен (значит, дело не в нём, а в занятом порте или правах)"
    else
      echo "$out" | grep -v -e '\[Info\]' -e 'Penetrates Everything' -e 'A unified platform' | tail -10
    fi
  fi
done
[[ -f "$REJECTED" ]] || info "отвергнутого конфига нет — либо всё принято, либо агент старый"

echo
echo "== Порты подключений =="
# Порты, которые панель просит слушать, — из конфига; что их занимает — из ss.
ports="$(grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]\+' "$CONFIG" 2>/dev/null |
         grep -o '[0-9]\+' | sort -un)"
if [[ -z "$ports" ]]; then
  info "в конфиге нет портов (панель ещё не прислала подключения)"
fi
for port in $ports; do
  if command -v ss >/dev/null 2>&1; then
    line="$(ss -ltnpH "sport = :$port" 2>/dev/null | head -1)"
  else
    line=""
  fi
  if [[ -z "$line" ]]; then
    info "порт $port свободен (никто не слушает)"
  elif echo "$line" | grep -q xray; then
    ok "порт $port слушает xray"
    # Слушать мало: до порта ещё должны доходить снаружи. Самая частая
    # причина «подключается, но интернета нет» — закрытый порт.
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
      if ufw status 2>/dev/null | grep -qE "^($port|$port/tcp)[[:space:]]+ALLOW"; then
        ok "порт $port открыт в ufw"
      else
        bad "порт $port НЕ открыт в ufw — снаружи до него не достучаться"
        bad "открыть: ufw allow ${port}/tcp"
      fi
    fi
  else
    who="$(echo "$line" | sed 's/.*users:((//; s/).*//' | tr -d '"')"
    bad "порт $port занят другой программой: ${who:-неизвестно}"
    bad "это и есть причина падения — освободите порт или смените его в панели"
  fi
done

if [[ -n "$ports" ]]; then
  echo
  echo "== Проверьте порты снаружи =="
  info "у хостера может быть свой файрвол, ufw о нём не знает."
  info "со своего компьютера: Test-NetConnection <адрес> -Port <порт>  (PowerShell)"
  info "или:                  nc -vz <адрес> <порт>                    (Linux/Mac)"
fi

echo
echo "== Прочее =="
if [[ -d /usr/local/etc/xray ]]; then
  ok "каталог /usr/local/etc/xray на месте"
else
  bad "нет каталога /usr/local/etc/xray"
fi
if command -v ufw >/dev/null 2>&1; then
  info "ufw: $(ufw status 2>/dev/null | head -1)"
fi

echo
echo "Готово. Строки [ !! ] — то, что стоит починить."
