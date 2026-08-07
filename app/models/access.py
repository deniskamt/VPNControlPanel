from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class UserNodeAccess(Base):
    """Настройка доступа пользователя к конкретному серверу.

    Строка — это исключение из умолчания: нет строки — сервер доступен и
    отдельного лимита на нём нет. Так добавление новой ноды не требует
    трогать всех пользователей, а точечные ограничения остаются возможны.
    """

    __tablename__ = "user_node_access"
    __table_args__ = (UniqueConstraint("user_id", "node_id", name="uq_user_node"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    node_id: Mapped[int] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"), index=True
    )

    is_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    # Отдельный лимит трафика на этом сервере. NULL — только общий лимит.
    data_limit: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    used_traffic: Mapped[int] = mapped_column(BigInteger, default=0)
    reset_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="node_access")  # noqa: F821
    node: Mapped["Node"] = relationship()  # noqa: F821

    @property
    def limited(self) -> bool:
        return bool(self.data_limit) and self.used_traffic >= self.data_limit

    @property
    def blocked(self) -> bool:
        """Сервер закрыт для пользователя: вручную или исчерпанным лимитом."""
        return not self.is_allowed or self.limited
