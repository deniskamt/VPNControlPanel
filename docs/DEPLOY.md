# Установка панели на сервер

Панель — обычное веб-приложение: Python-процесс за nginx плюс Postgres.
Держать её на VPN-сервере не обязательно и не нужно: она управляет нодами
по сети, а сама может стоять где угодно.

**Что понадобится**

- сервер с Ubuntu 22.04/24.04 или Debian 12, 1 vCPU и 1 ГБ RAM хватит
  (панель не гоняет трафик пользователей, только управляет нодами);
- домен, направленный A-записью на этот сервер;
- **тот самый домен, на котором сейчас работают подписки Marzban**
  (`nexlovpn.online`) — его тоже нужно перенаправить на панель, иначе
  выданные пользователям ссылки перестанут открываться.

Домены могут быть разными: например, `panel.nexlovpn.online` для админки и
`nexlovpn.online` для подписок. Оба должны вести на этот сервер.

---

## Пробная установка на одном сервере (без домена)

Чтобы просто посмотреть, как всё работает, домен не нужен: панель поднимется
по IP, а REALITY не требует сертификата. Панель и нода могут жить на одной
машине. Годится для проверки, но **не для боевого запуска** — по http пароль
и токены идут открытым текстом.

**1. Поставить панель**

```bash
apt update && apt install -y git
git clone https://github.com/deniskamt/VPNControlPanel.git /opt/vpn-panel
cd /opt/vpn-panel
bash scripts/install_panel.sh
```

На вопрос «Домен или IP панели» ответьте IP сервера. Скрипт увидит, что это
не домен, перейдёт на `http`, поднимет панель на всех интерфейсах и не станет
ждать nginx. Остальные вопросы можно проматывать Enter'ом. В конце он напечатает
адрес входа и пароль.

**2. Открыть порт**

```bash
ufw allow from <ваш домашний IP> to any port 8000 proto tcp   # безопаснее
# или, если IP плавающий:
ufw allow 8000/tcp
```

Заходим на `http://<IP сервера>:8000`.

**3. Добавить сервер и поставить агента**

«Серверы» → «Добавить сервер»:

- **Название** — любое, попадёт в имя профиля у клиента;
- **Адрес для клиентов** — IP сервера;
- **Адрес агента** — `127.0.0.1`, если панель и нода на одной машине
  (тогда порт агента наружу открывать не нужно);
- **Токен агента** — уже подставлен, скопируйте его.

Сохраните, затем выполните на сервере команду из блока внизу страницы:

```bash
curl -fsSL http://<IP сервера>:8000/install/install_agent.sh -o install_agent.sh
AGENT_TOKEN=<токен из формы> PANEL_URL=http://<IP сервера>:8000 bash install_agent.sh
```

Скрипт поставит Xray-core и агента. Сервер пока будет красным — inbound'ов
ещё нет, это нормально.

**4. Сделать ключи REALITY**

Xray появился на сервере вместе с агентом, так что теперь можно:

```bash
xray x25519
```

Команда выдаст пару `Private key` / `Public key` — они понадобятся оба.

**5. Создать подключение**

«Подключения» → «Добавить подключение»:

- Tag: `VLESS-REALITY`, протокол `vless`, порт `443`,
  транспорт `tcp`, шифрование `reality`;
- в поле параметров:

```json
{
  "dest": "www.microsoft.com:443",
  "serverNames": ["www.microsoft.com"],
  "privateKey": "<Private key из xray x25519>",
  "publicKey": "<Public key из xray x25519>",
  "shortIds": ["ab12"],
  "fingerprint": "chrome",
  "flow": "xtls-rprx-vision"
}
```

- отметить галочкой свой сервер и сохранить.

`privateKey` уезжает на ноду в конфиг, `publicKey` попадает в ссылку клиента —
нужны оба. `shortIds` — произвольная шестнадцатеричная строка чётной длины.
Порт 443 на сервере должен быть свободен.

Панель сама зальёт конфиг, и через несколько секунд сервер станет зелёным.
Если нет — «Журнал» покажет, что именно не понравилось Xray.

**6. Проверить**

«Пользователи» → «Добавить пользователя» → скопировать ссылку подписки и
вставить её в v2rayNG, NekoBox или Hiddify как подписку. Клиент подтянет
профиль, и соединение должно подняться.

Когда наиграетесь — берите домен, ставьте nginx с сертификатом и меняйте
`PANEL_URL` и `SUBSCRIPTION_BASE_URL` в `.env` на `https://...`.

---

## Быстрый путь (скрипт)

```bash
apt update && apt install -y git
git clone https://github.com/deniskamt/VPNControlPanel.git /opt/vpn-panel
cd /opt/vpn-panel
bash scripts/install_panel.sh
```

Скрипт спросит домены и сделает всё сам: поставит Postgres, создаст базу и
пользователя со случайным паролем, соберёт виртуальное окружение, сгенерирует
`.env` с ключами, поднимет systemd-сервис `vpn-panel` на `127.0.0.1:8000`.
В конце он напечатает логин и пароль администратора — **сохраните их сразу**,
второй раз пароль не показывается.

Дальше остаётся [настроить nginx и сертификат](#nginx-и-сертификат).

---

## Ручной путь

Если хочется понимать каждый шаг или сервер нестандартный.

### 1. Пакеты

```bash
apt update
apt install -y python3 python3-venv python3-dev build-essential \
               postgresql nginx certbot python3-certbot-nginx git curl
```

### 2. База данных

```bash
systemctl enable --now postgresql

su - postgres -c "psql -c \"CREATE ROLE vpnpanel WITH LOGIN PASSWORD 'ПРИДУМАЙТЕ_ПАРОЛЬ';\""
su - postgres -c "createdb -O vpnpanel vpnpanel"
```

### 3. Код и окружение

```bash
git clone https://github.com/deniskamt/VPNControlPanel.git /opt/vpn-panel
cd /opt/vpn-panel

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

### 4. Настройки

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # для SECRET_KEY
nano .env
chmod 600 .env
```

Минимум, что нужно заполнить:

```ini
SECRET_KEY=<длинная случайная строка>
PANEL_URL=https://panel.nexlovpn.online
DATABASE_URL=postgresql://vpnpanel:ПАРОЛЬ@127.0.0.1:5432/vpnpanel

ADMIN_USERNAME=admin
ADMIN_PASSWORD=<пароль для первого входа>

SUBSCRIPTION_BASE_URL=https://nexlovpn.online   # домен, который уже у пользователей
SUBSCRIPTION_PATH=c                             # префикс пути, как в Marzban
SUBSCRIPTION_SECRET=                            # заполняется на шаге миграции
```

`SUBSCRIPTION_BASE_URL` и `SUBSCRIPTION_PATH` должны в точности совпадать с
тем, что было в Marzban, — из них складывается ссылка, которая уже лежит
в приложениях у пользователей.

Администратор создаётся при первом запуске и только если в базе нет ни
одного админа. Менять `ADMIN_PASSWORD` потом бессмысленно — пароль уже в базе.

### 5. Автозапуск

```bash
cat > /etc/systemd/system/vpn-panel.service <<'EOF'
[Unit]
Description=VPN Control Panel
After=network.target postgresql.service

[Service]
Type=simple
WorkingDirectory=/opt/vpn-panel
EnvironmentFile=/opt/vpn-panel/.env
ExecStart=/opt/vpn-panel/.venv/bin/uvicorn app.main:app \
    --host 127.0.0.1 --port 8000 \
    --proxy-headers --forwarded-allow-ips '*'
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpn-panel
systemctl status vpn-panel
```

Панель намеренно слушает только `127.0.0.1` — наружу её пускает nginx.

---

## Nginx и сертификат

```bash
cat > /etc/nginx/sites-available/vpn-panel <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name panel.nexlovpn.online nexlovpn.online;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/vpn-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

Сертификат — certbot сам перепишет конфиг под HTTPS и настроит редирект:

```bash
certbot --nginx -d panel.nexlovpn.online -d nexlovpn.online
```

Заголовок `X-Forwarded-Proto` обязателен: по нему панель понимает, что
работает по HTTPS, и ставит cookie сессии с флагом `Secure`.

Проверка:

```bash
curl -s https://panel.nexlovpn.online/healthz     # {"status":"ok"}
```

---

## Файрвол

```bash
ufw allow 22/tcp
ufw allow 80,443/tcp
ufw enable
```

Порт агента (8443) на **нодах** должен быть открыт только для адреса панели:

```bash
# на каждом VPN-сервере
ufw allow from <IP панели> to any port 8443 proto tcp
ufw deny 8443/tcp
```

Токен агента — единственное, что защищает ноду от постороннего управления,
поэтому ограничение по IP здесь не формальность.

---

## Перенос данных из Marzban

Делается один раз, после того как панель поднялась.

```bash
cd /opt/vpn-panel
.venv/bin/pip install -r requirements-migrate.txt

.venv/bin/python scripts/migrate_from_marzban.py \
    --source "sqlite:////var/lib/marzban/db.sqlite3" \
    --xray-config /var/lib/marzban/xray_config.json \
    --dry-run
```

Для MySQL: `--source "mysql+pymysql://user:pass@127.0.0.1/marzban"`.
Если Marzban на другом сервере — снимите дамп и положите файл рядом, либо
откройте доступ к его базе с адреса панели.

Скрипт напечатает строку вида `SUBSCRIPTION_SECRET=...`. Впишите её в `.env`
и перезапустите панель:

```bash
nano .env                        # SUBSCRIPTION_SECRET=<из вывода скрипта>
systemctl restart vpn-panel
```

Затем прогоните перенос уже без `--dry-run`. Скрипт идемпотентен: перед
самым переключением домена его можно запустить ещё раз, чтобы догнать
оплаты, прошедшие за время подготовки.

После переноса зайдите в панель → «Подключения» и впишите `publicKey` для
REALITY: в серверном конфиге его нет, он получается на ноде командой
`xray x25519 -i <privateKey>`. Без него клиенты не подключатся.

---

## Подключение серверов

В панели: «Серверы» → «Добавить сервер». Скопируйте команду из блока внизу
страницы и выполните её на VPN-сервере под root:

```bash
curl -fsSL https://panel.nexlovpn.online/install/install_agent.sh -o install_agent.sh
AGENT_TOKEN=<токен из формы> PANEL_URL=https://panel.nexlovpn.online bash install_agent.sh
```

Скрипт ставит Xray-core и агента, поднимает сервис `vpn-agent`. Через
полминуты сервер в панели станет зелёным, и конфиг уедет на него сам.

Панель и нода могут жить на одном сервере — тогда в поле «Адрес агента»
укажите `127.0.0.1`, и порт наружу открывать вообще не нужно.

---

## Проверка перед переключением

1. Заведите тестового пользователя, откройте его ссылку подписки, подключитесь.
2. Возьмите **старую** ссылку реального пользователя (из Marzban) и откройте
   её на домене панели — должны отдаться конфиги. Это главная проверка: если
   она проходит, переключение домена пройдёт для людей незаметно.
3. Переключите DNS домена подписок на панель и погасите Marzban.

---

## Эксплуатация

```bash
journalctl -u vpn-panel -f          # логи панели
systemctl restart vpn-panel         # перезапуск
journalctl -u vpn-agent -f          # логи агента (на ноде)
```

### Панель уже стоит — что делать дальше

Переустанавливать её ради изменений не нужно. Смотря что требуется:

| Задача | Что сделать |
| --- | --- |
| поменять адрес, домен, токен бота и прочие настройки | `nano /opt/vpn-panel/.env` → `systemctl restart vpn-panel` |
| обновить код панели | `git pull` → `pip install -r requirements.txt` → `systemctl restart vpn-panel` |
| забыт пароль администратора | `.venv/bin/python scripts/admin.py set-password --username admin` |
| завести второго администратора | `.venv/bin/python scripts/admin.py set-password --username operator` |
| посмотреть, кто есть | `.venv/bin/python scripts/admin.py list` |
| начать с чистого листа | `REINSTALL=1 bash scripts/install_panel.sh` (см. предупреждение ниже) |

Скрипт установки можно запускать повторно — он увидит существующий `.env` и
переведёт себя в режим обновления: сохранит `SECRET_KEY`, `SUBSCRIPTION_SECRET`,
доступ к базе, пароль администратора и правки в настройках, обновив только
зависимости и systemd-сервис. Пароль при этом не печатается: он хранится в
базе, и переменная `ADMIN_PASSWORD` на него уже не влияет — она срабатывает
единственный раз, когда админов ещё нет.

**`REINSTALL=1` перевыпускает `SECRET_KEY`.** Если `SUBSCRIPTION_SECRET` не
задан явно, токены подписок подписываются именно им — значит, все выданные
пользователям ссылки перестанут открываться. Данные в базе при этом
сохраняются, но подписки придётся раздавать заново.

**Обновление кода вручную:**

```bash
cd /opt/vpn-panel
git pull
.venv/bin/pip install -r requirements.txt
systemctl restart vpn-panel
```

При старте панель создаёт недостающие таблицы, но не меняет существующие
колонки. Если в обновлении менялась схема, об этом будет сказано в описании
изменений — такие правки пока применяются вручную через `psql`.

**Резервные копии.** Ценна только база: в ней ключи пользователей, при её
потере придётся перевыпускать все подписки.

```bash
su - postgres -c "pg_dump vpnpanel" | gzip > /root/vpnpanel-$(date +%F).sql.gz
```

Строку в cron — раз в сутки:

```
0 4 * * * su - postgres -c "pg_dump vpnpanel" | gzip > /root/backup/vpnpanel-$(date +\%F).sql.gz
```

Отдельно сохраните `SECRET_KEY` и `SUBSCRIPTION_SECRET` из `.env`: без
второго не проверятся токены подписок даже при целой базе.

---

## Вариант с Railway

Если не хочется возиться с сервером — панель разворачивается и на Railway
(`railway.json` и `Procfile` уже в репозитории):

1. New Project → Deploy from GitHub repo → `VPNControlPanel`.
2. Add Postgres — `DATABASE_URL` подставится автоматически.
3. В Variables задать `SECRET_KEY`, `PANEL_URL`, `ADMIN_USERNAME`,
   `ADMIN_PASSWORD`, `SUBSCRIPTION_BASE_URL`, `SUBSCRIPTION_PATH`,
   `SUBSCRIPTION_SECRET`.
4. Settings → Networking → привязать домен подписок.

Ноды при этом всё равно остаются на обычных VPS: Railway управляет ими по
сети. Учтите, что агент придётся открыть в интернет (Railway не даёт
фиксированного исходящего IP), поэтому токен агента должен быть длинным,
а `agent_tls` — включённым.
