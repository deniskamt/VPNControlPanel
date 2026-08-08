from typing import Optional

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Setting(Base):
    """Настройки, которые меняют из панели, а не из .env.

    В переменных окружения оставлено то, что задаётся один раз при установке
    (адреса, ключи, доступ к базе). Всё, что администратор правит по ходу
    работы — текст объявления для клиентов, ссылка на поддержку, — живёт
    здесь: перезапускать панель ради правки текста не нужно.
    """

    __tablename__ = "panel_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
