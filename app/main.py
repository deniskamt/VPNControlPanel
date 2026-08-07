"""Точка входа панели."""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger
from sqlalchemy import func, select
from starlette.middleware.sessions import SessionMiddleware

from app.api import compat, subscription_routes
from app.api.deps import NotAuthenticated, redirect_to_login
from app.core.config import settings
from app.core.database import SessionLocal, engine
from app.core.logging import setup_logging
from app.core.security import hash_password
from app.models.admin import Admin
from app.models.base import Base
from app.services.worker import start_workers, stop_workers
from app.web import auth, dashboard, inbounds, logs, nodes, users

BASE_DIR = Path(__file__).resolve().parent


async def _prepare_database() -> None:
    """Создаём таблицы, если их ещё нет, и первого администратора."""
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with SessionLocal() as session:
        admins = await session.scalar(select(func.count()).select_from(Admin))
        if not admins:
            session.add(
                Admin(
                    username=settings.ADMIN_USERNAME,
                    hashed_password=hash_password(settings.ADMIN_PASSWORD),
                    is_sudo=True,
                )
            )
            await session.commit()
            logger.warning(
                f"Создан администратор «{settings.ADMIN_USERNAME}». "
                "Смените пароль (ADMIN_PASSWORD) после первого входа."
            )


def _check_secrets() -> None:
    """Слабый ключ подписи — тихая, но серьёзная дыра: им подписываются
    сессии панели, а при пустом SUBSCRIPTION_SECRET ещё и токены подписок."""
    if settings.SECRET_KEY == "change-me-please":
        logger.error(
            "SECRET_KEY не задан и используется значение по умолчанию. "
            "Сгенерируйте его: python -c \"import secrets; "
            "print(secrets.token_urlsafe(48))\""
        )
    elif len(settings.SECRET_KEY) < 32:
        logger.warning(
            f"SECRET_KEY короткий ({len(settings.SECRET_KEY)} символов), "
            "рекомендуется не меньше 32"
        )


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    setup_logging()
    _check_secrets()
    await _prepare_database()
    tasks = start_workers()
    logger.info(
        f"Панель запущена. Подписки: {settings.subscription_base}/"
        f"{settings.SUBSCRIPTION_PATH}/<token>"
    )
    try:
        yield
    finally:
        await stop_workers(tasks)
        await engine.dispose()


app = FastAPI(
    title="VPN Control Panel",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url=None,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="vpnpanel_session",
    max_age=14 * 24 * 3600,
    same_site="lax",
    https_only=settings.PANEL_URL.startswith("https://"),
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.exception_handler(NotAuthenticated)
async def _not_authenticated(request: Request, _: NotAuthenticated):
    return redirect_to_login(request)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


# Файлы для установки агента на ноду. Отдаются без авторизации: секретов в
# них нет, а curl с сервера не сможет авторизоваться сессией панели.
@app.get("/install/agent.py", include_in_schema=False)
async def install_agent_source() -> FileResponse:
    return FileResponse(
        BASE_DIR.parent / "agent" / "agent.py", media_type="text/x-python"
    )


@app.get("/install/install_agent.sh", include_in_schema=False)
async def install_agent_script() -> FileResponse:
    return FileResponse(
        BASE_DIR.parent / "scripts" / "install_agent.sh", media_type="text/x-shellscript"
    )


# Marzban-совместимый API — им пользуются боты и мобильное приложение.
app.include_router(compat.router)

# Подписки. Основной префикс берётся из настроек (у Marzban это был /c),
# дополнительно слушаем /sub — стандартный путь Marzban по умолчанию.
app.include_router(
    subscription_routes.router, prefix=f"/{settings.SUBSCRIPTION_PATH}"
)
if settings.SUBSCRIPTION_PATH != "sub":
    app.include_router(subscription_routes.router, prefix="/sub", include_in_schema=False)

# Веб-панель.
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(nodes.router)
app.include_router(users.router)
app.include_router(inbounds.router)
app.include_router(logs.router)
