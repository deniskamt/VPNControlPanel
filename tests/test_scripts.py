"""Проверки скриптов установки и переезда.

Ошибка в bash-скрипте обнаруживается на боевом сервере в самый неподходящий
момент, поэтому хотя бы синтаксис и поведение без аргументов проверяем здесь.
"""

import subprocess
from pathlib import Path

import pytest

SCRIPTS = sorted((Path(__file__).resolve().parent.parent / "scripts").glob("*.sh"))


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_script_syntax_is_valid(script: Path) -> None:
    result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "script", ["setup_domain.sh", "restore_panel.sh"]
)
def test_script_without_arguments_stops(script: str) -> None:
    """Скрипты переезда без обязательного аргумента не должны ничего делать."""
    path = Path(__file__).resolve().parent.parent / "scripts" / script
    result = subprocess.run(["bash", str(path)], capture_output=True, text=True)
    assert result.returncode == 1


def test_setup_domain_puts_every_domain_into_nginx_and_certificate() -> None:
    """Ключ --also нужен при смене домена: старые ссылки подписок ведут на
    прежний адрес, и панель должна отвечать на обоих."""
    text = (Path(__file__).resolve().parent.parent / "scripts" / "setup_domain.sh").read_text()
    assert "--also) EXTRA_DOMAINS+=" in text
    # Имена сервера в nginx и список -d для certbot берутся из одного списка.
    assert 'SERVER_NAMES="${ALL_DOMAINS[*]}"' in text
    assert 'for name in "${ALL_DOMAINS[@]}"; do CERTBOT_ARGS+=(-d "$name"); done' in text


def test_restore_keeps_local_database_and_carries_secrets() -> None:
    """Из архива приезжают ключи подписок, а адрес базы остаётся местный —
    перепутать эти два списка значит либо сломать ссылки, либо базу."""
    text = (Path(__file__).resolve().parent.parent / "scripts" / "restore_panel.sh").read_text()
    for line in (
        'set_env DATABASE_URL "$LOCAL_DB"',
        'set_env PANEL_URL "$LOCAL_PANEL"',
        'set_env SUBSCRIPTION_BASE_URL "$LOCAL_SUB"',
    ):
        assert line in text
    # Перед заменой базы делается снимок — без него откатываться будет нечем.
    assert "vpn-panel-before-restore" in text


def test_worker_serves_nodes_in_parallel():
    """Одна недоступная нода не должна задерживать остальные.

    Обход по очереди означал таймаут на каждую мёртвую ноду: при десятке
    серверов круг растягивался на минуты, и только что созданное
    подключение подолгу не появлялось на живых.
    """
    from pathlib import Path

    source = Path("app/services/worker.py").read_text("utf-8")

    assert "asyncio.gather" in source
    assert "PARALLEL_NODES" in source
    # Последовательного обхода в цикле опроса больше нет.
    assert "for node in nodes:" not in source


def test_inbound_diagnostic_names_the_three_causes():
    """Три разные беды выглядят одинаково — «не подключается»."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "diagnose_inbounds", Path("scripts/diagnose_inbounds.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Порт, на котором заведомо никого нет.
    assert module.check_tcp("127.0.0.1", 9) in ("закрыт", "таймаут")
    # UDP молчит по своей природе, и скрипт об этом говорит прямо.
    assert "UDP" in module.check_udp("127.0.0.1", 9)

    text = Path("scripts/diagnose_inbounds.py").read_text("utf-8")
    for cause in ("не раскатано", "конфиг не доехал", "файрвол"):
        assert cause in text or cause.split()[0] in text


def test_dest_scanner_checks_what_reality_needs():
    """Домен из гайда часто не годится, и это выясняется только на живых
    пользователях: нет TLS 1.3 или HTTP/2 — рукопожатие рассыпается."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "pick_dest", Path("scripts/pick_dest.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Маску в сертификате понимаем так же, как её понимает TLS.
    assert module.covers("www.example.com", ["*.example.com"])
    assert module.covers("example.com", ["example.com"])
    assert not module.covers("example.com", ["*.example.com"])
    assert not module.covers("evil.com", ["*.example.com"])

    # Несуществующий домен не должен ронять скрипт.
    ok, note, _ = module.probe("this-domain-does-not-exist.invalid")
    assert ok is False and note


def test_front_script_does_not_terminate_tls_itself():
    """Передний сервер обязан отдавать поток байт в байт.

    Обычный proxy_pass внутри http {} отвечает клиенту своим сертификатом,
    и REALITY у клиента не сходится. Проверено на живом nginx: с ssl_preread
    по имени домена поток уходит на нужный адрес, TLS остаётся нетронутым.
    """
    text = (Path(__file__).resolve().parent.parent / "scripts" / "setup_front.sh").read_text()

    assert "ssl_preread on;" in text
    # Внутри heredoc знак доллара экранирован — подставляет его nginx, не bash.
    assert r"proxy_pass \$vpn_front_upstream;" in text
    # Никакого http-прокси и никакого своего сертификата в потоке.
    assert "ssl_certificate" not in text
    assert "proxy_set_header" not in text


def test_front_script_frees_443_and_keeps_the_panel_reachable():
    """Порт 443 отдаётся stream, а http-серверы уезжают на localhost.

    Если этого не сделать, nginx падает с «Address already in use» — и вместе
    с ним уходит панель. Имена переехавших серверов обязаны попасть в правила,
    иначе они перестанут открываться.
    """
    text = (Path(__file__).resolve().parent.parent / "scripts" / "setup_front.sh").read_text()

    assert 'LOCAL_HTTPS="127.0.0.1:8443"' in text
    assert 'listen ${LOCAL_HTTPS}' in text
    assert 'printf \'%s %s;\\n\' "$name" "$LOCAL_HTTPS"' in text
    assert "default ${LOCAL_HTTPS};" in text


def test_front_script_survives_a_server_without_ipv6():
    """listen [::] роняет nginx целиком там, где IPv6 выключен."""
    text = (Path(__file__).resolve().parent.parent / "scripts" / "setup_front.sh").read_text()

    assert "/proc/net/if_inet6" in text
    # Безусловной строки с IPv6 в шаблоне конфига быть не должно.
    assert "\n    listen [::]:443 reuseport;\n" not in text.split("cat > \"$FRONT_CONF\"")[-1]


def test_front_script_rolls_back_when_nginx_refuses():
    """Конфиг переднего сервера трогает работающую панель — откат обязателен."""
    text = (Path(__file__).resolve().parent.parent / "scripts" / "setup_front.sh").read_text()

    assert "cp -a /etc/nginx \"$BACKUP\"" in text
    assert text.count("rollback") >= 3
    assert "if ! nginx -t; then" in text
