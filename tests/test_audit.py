"""Журнал не должен ломать то, что записывает.

Перечисление изменений на девяти серверах не влезало в колонку, Postgres
отвечал «value too long», и вместо сохранённых настроек пользователь получал
Internal Server Error. Запись в журнал — не та причина, по которой действие
имеет право не выполниться.
"""

from app.services.audit import LIMITS, fit


def test_limits_come_from_the_table():
    # Если колонку в модели удлинят, подрезка должна поехать следом.
    assert LIMITS["message"] == 1024
    assert LIMITS["target"] == 128
    assert LIMITS["actor"] == 64


def test_short_values_are_untouched():
    assert fit("message", "убрано «VLESS-REALITY»") == "убрано «VLESS-REALITY»"
    assert fit("message", None) is None
    # Поля без ограничения длины (JSONB, даты) проходят как есть.
    assert fit("details", "x" * 5000) == "x" * 5000


def test_long_values_are_trimmed_to_the_column():
    long_message = "Сервер номер 1: убрано «VLESS-REALITY»; " * 40

    trimmed = fit("message", long_message)

    assert len(trimmed) == LIMITS["message"]
    assert trimmed.endswith("…"), "обрезку видно по многоточию"
    assert trimmed.startswith("Сервер номер 1")


def test_no_field_can_overflow_its_column():
    """Забытое поле обвалится ровно так же, как раньше обваливалось сообщение."""
    import asyncio

    from app.services.audit import log_action

    class Collector:
        """Сессии тут не нужно ничего, кроме add."""

        def __init__(self):
            self.entry = None

        def add(self, entry):
            self.entry = entry

    session = Collector()
    huge = "я" * 4000
    asyncio.run(
        log_action(
            session,
            action=huge,
            actor=huge,
            target=huge,
            target_type=huge,
            message=huge,
            level=huge,
            ip=huge,
            details={"полностью": huge},
        )
    )

    for field, limit in LIMITS.items():
        value = getattr(session.entry, field)
        assert value is None or len(value) <= limit, field
    # Подробности — в JSONB, их не режем.
    assert session.entry.details["полностью"] == huge
