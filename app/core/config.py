"""Конфигурация панели. Все значения читаются из переменных окружения / .env."""

from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Общее -------------------------------------------------------------
    DEBUG: bool = False
    # Ключ для подписи cookie-сессий панели и админских JWT.
    SECRET_KEY: str = "change-me-please"
    # Внешний адрес панели, без слэша на конце: https://panel.example.com
    PANEL_URL: str = "http://localhost:8000"

    # --- База данных -------------------------------------------------------
    # Принимает и postgresql://, и postgresql+asyncpg:// — нормализуется ниже.
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/vpnpanel"
    DB_ECHO: bool = False

    # --- Первый администратор ---------------------------------------------
    # Создаётся при первом старте, если в базе нет ни одного админа.
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"

    # --- Подписки ----------------------------------------------------------
    # Домен, который отдаётся пользователям в subscription_url. Должен
    # совпадать с доменом старой панели Marzban, иначе выданные ранее ссылки
    # перестанут открываться.
    SUBSCRIPTION_BASE_URL: str = ""
    # Префикс пути подписки. В текущей установке Marzban это "c"
    # (https://nexlovpn.online/c/<token>).
    SUBSCRIPTION_PATH: str = "c"
    # Секрет, которым подписываются токены подписок. ОБЯЗАТЕЛЬНО перенести из
    # таблицы `jwt` старой базы Marzban — иначе старые ссылки не пройдут
    # проверку подписи. Если пусто, используется SECRET_KEY.
    SUBSCRIPTION_SECRET: str = ""
    # Заголовок профиля в клиентских приложениях.
    SUBSCRIPTION_TITLE: str = "NexloVPN"
    # Через сколько часов клиент должен обновлять подписку.
    SUBSCRIPTION_UPDATE_INTERVAL: int = 12

    # --- Токены API --------------------------------------------------------
    # Время жизни админского токена (/api/admin/token), минуты.
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # --- Значения по умолчанию для новых пользователей ---------------------
    DEFAULT_DATA_LIMIT: int = 0  # 0 = безлимит
    DEFAULT_DATA_LIMIT_RESET_STRATEGY: str = "no_reset"

    # --- Фоновые задачи ----------------------------------------------------
    # Как часто опрашивать ноды: здоровье + сбор трафика, секунды.
    NODE_POLL_INTERVAL: int = 30
    # Как часто проверять истёкшие подписки и превышение лимита, секунды.
    ENFORCE_INTERVAL: int = 60
    # Таймаут запроса к агенту ноды, секунды.
    NODE_TIMEOUT: int = 10

    # --- Лимит устройств ---------------------------------------------------
    # За какое окно считать уникальные адреса подключений, минуты.
    DEVICE_WINDOW_MINUTES: int = 5
    # Что делать при превышении: warn — только запись в журнал и уведомление,
    # disable — ещё и отключить пользователя (включать обратно вручную).
    DEVICE_LIMIT_ACTION: str = "warn"

    # --- Уведомления в Telegram -------------------------------------------
    TELEGRAM_BOT_TOKEN: str = ""
    # Строка, а не List[int]: pydantic-settings пытается разобрать поля
    # составных типов как JSON ещё до валидаторов, и пустое значение в .env
    # (TELEGRAM_ADMIN_IDS=) роняет запуск. Разбираем сами — см. telegram_admin_ids.
    TELEGRAM_ADMIN_IDS: str = ""
    # Слать ли уведомления о падении/подъёме нод.
    NOTIFY_NODE_STATUS: bool = True

    @field_validator("DATABASE_URL")
    @classmethod
    def _normalize_database_url(cls, value: str) -> str:
        """Railway отдаёт postgresql://, а нам нужен асинхронный драйвер."""
        if value.startswith("postgres://"):
            value = value.replace("postgres://", "postgresql://", 1)
        if value.startswith("postgresql://"):
            value = value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @field_validator("PANEL_URL", "SUBSCRIPTION_BASE_URL")
    @classmethod
    def _strip_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("SUBSCRIPTION_PATH")
    @classmethod
    def _strip_sub_path(cls, value: str) -> str:
        return value.strip("/")

    @property
    def telegram_admin_ids(self) -> List[int]:
        """Список ID из строки вида «123456789, 987654321»."""
        ids: List[int] = []
        for part in self.TELEGRAM_ADMIN_IDS.replace(" ", "").split(","):
            if not part:
                continue
            try:
                ids.append(int(part))
            except ValueError:
                # Одна опечатка не должна ломать запуск панели целиком.
                continue
        return ids

    @property
    def sync_database_url(self) -> str:
        """Синхронный URL — нужен Alembic и скрипту миграции."""
        return self.DATABASE_URL.replace("+asyncpg", "")

    @property
    def subscription_secret(self) -> str:
        return self.SUBSCRIPTION_SECRET or self.SECRET_KEY

    @property
    def subscription_base(self) -> str:
        return self.SUBSCRIPTION_BASE_URL or self.PANEL_URL

    def subscription_url(self, token: str) -> str:
        return f"{self.subscription_base}/{self.SUBSCRIPTION_PATH}/{token}"


settings = Settings()
