"""Пароли администраторов.

Отдельный смысл этих тестов — совместимость с Marzban: его админы
переносятся вместе с хешами, и вход со старым паролем должен работать.
"""

import bcrypt
import pytest

from app.core.security import (
    create_admin_token,
    decode_admin_token,
    hash_password,
    verify_password,
)


def test_hash_and_verify_roundtrip():
    hashed = hash_password("Пароль-123")
    assert hashed.startswith("$2b$")
    assert verify_password("Пароль-123", hashed)
    assert not verify_password("Пароль-124", hashed)


def test_marzban_hash_accepted():
    """Хеш, сделанный по-старому (passlib bcrypt), обязан подойти."""
    # Ровно то, что лежало бы в колонке admins.hashed_password у Marzban.
    marzban_hash = bcrypt.hashpw(b"old-admin-password", bcrypt.gensalt(rounds=12))
    assert verify_password("old-admin-password", marzban_hash.decode())
    assert not verify_password("wrong", marzban_hash.decode())


@pytest.mark.parametrize("broken", ["", "не хеш", "$2b$12$слишком-короткий", "null"])
def test_broken_hash_denies_instead_of_crashing(broken):
    # Битая строка в базе не должна ронять форму входа пятисоткой.
    assert verify_password("любой", broken) is False


def test_very_long_password_does_not_crash():
    """bcrypt считает только 72 байта и в 5.x ругается на длинные строки."""
    password = "д" * 200
    hashed = hash_password(password)
    assert verify_password(password, hashed)


def test_admin_token_roundtrip():
    token = create_admin_token("admin")
    assert decode_admin_token(token) == "admin"


def test_foreign_token_rejected():
    assert decode_admin_token("не.токен.вовсе") is None
    assert decode_admin_token("") is None
