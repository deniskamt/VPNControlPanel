"""Пароли админов и токены доступа.

Хеши паролей — bcrypt, тот же формат, что в Marzban, поэтому админов можно
перенести миграцией и войти со старым паролем.
"""

from datetime import datetime, timedelta
from typing import Optional

import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(password, hashed)
    except ValueError:
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
