"""Расшифровка ошибок Xray в понятный совет."""

import pytest

from app.services.xray_errors import explain


def test_busy_port_gets_the_most_common_advice():
    """Панель за nginx держит 443 — самая частая причина падения ядра."""
    message = explain(
        "Конфиг не принят Xray: Failed to start: main: failed to listen on "
        "port 443: address already in use"
    )
    assert "порт уже занят" in message
    # Подсказка предлагает оба выхода: перенести подключение или освободить 443.
    assert "перенесите подключение" in message
    assert "освободите 443" in message
    # Исходный текст остаётся: по нему видно, какой именно порт.
    assert "443" in message


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("tls: failed to find any PEM data", "сертификат"),
        ("invalid private key for reality", "REALITY"),
        ("failed to initialize access logger", "журнала"),
        ("permission denied", "прав"),
        ("unknown protocol: hysteria", "версия Xray"),
        ("invalid method: 2022-blake3-aes-128-gcm key length", "Shadowsocks"),
    ],
)
def test_known_errors_get_hints(raw, expected):
    assert expected in explain(raw)


def test_unknown_error_returned_as_is():
    assert explain("что-то совсем новое") == "что-то совсем новое"


def test_empty_stays_empty():
    assert explain(None) == ""
    assert explain("") == ""
