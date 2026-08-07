"""Пароли админов и токены доступа.

Хеши паролей — bcrypt, тот же формат, что в Marzban, поэтому админов можно
перенести миграцией и войти со старым паролем.

Библиотека bcrypt используется напрямую: passlib тянет стандартный модуль
crypt, которого нет начиная с Python 3.13.
"""

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt

from app.core.config import settings

ALGORITHM = "HS256"

# bcrypt учитывает только первые 72 байта пароля, а в 5.x на более длинных
# бросает ошибку (passlib раньше обрезал молча). Обрезаем сами, иначе
# длинный пароль ронял бы и создание админа, и вход.
_MAX_PASSWORD_BYTES = 72


def _encode(password: str) -> bytes:
    return password.encode("utf-8")[:_MAX_PASSWORD_BYTES]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_encode(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_encode(password), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        # Чужой/битый формат хеша — не роняем логин, просто отказываем.
        return False


def create_admin_token(username: str, expire_minutes: Optional[int] = None) -> str:
    """Bearer-токен для /api/* (им пользуются боты и веб-панель)."""
    minutes = expire_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "access": "admin",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_admin_token(token: str) -> Optional[str]:
    """Возвращает username или None, если токен невалиден/просрочен."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    if payload.get("access") != "admin":
        return None
    return payload.get("sub")
