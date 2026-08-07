"""Окружение для тестов.

Настройки панели читаются один раз при импорте `app.core.config`, поэтому
переменные окружения нужно выставить до того, как любой тест затянет модули
приложения. conftest.py импортируется раньше тестовых модулей — это
единственное надёжное место.
"""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("SUBSCRIPTION_SECRET", "e2e-subscription-secret")
os.environ.setdefault("SUBSCRIPTION_BASE_URL", "https://vpn.example.com")
os.environ.setdefault("SUBSCRIPTION_PATH", "c")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "admin-password")
# Фоновые задачи в тестах не нужны — отодвигаем их подальше.
os.environ.setdefault("NODE_POLL_INTERVAL", "3600")
os.environ.setdefault("ENFORCE_INTERVAL", "3600")

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
if TEST_DATABASE_URL:
    os.environ["DATABASE_URL"] = TEST_DATABASE_URL
