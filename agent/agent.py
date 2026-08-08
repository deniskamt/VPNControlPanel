"""Агент ноды: единственное, что ставится на VPN-сервер.

Задачи агента:
  * принимать конфиг Xray от панели и применять его;
  * держать Xray живым (запускает его как дочерний процесс — systemd для
    самого Xray не нужен, агент и есть супервизор);
  * отдавать панели статистику трафика по пользователям и метрики сервера.

Зависимости: fastapi + uvicorn. Xray-ядро ставится отдельно (см.
scripts/install_agent.sh).

Запуск:
    AGENT_TOKEN=... python3 agent.py

Авторизация — общий bearer-токен, который панель хранит в поле node.agent_token.
Порт агента НЕ должен торчать в интернет: закройте его файрволом на все
адреса, кроме адреса панели.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional

import uvicorn
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query

# Версия агента. Увеличивается при каждом изменении этого файла: панель
# сравнивает её со своей и показывает, на каких нодах агент устарел.
AGENT_VERSION = 2

AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
AGENT_HOST = os.getenv("AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.getenv("AGENT_PORT", "8443"))
XRAY_BIN = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG = Path(os.getenv("XRAY_CONFIG", "/usr/local/etc/xray/config.json"))
XRAY_ASSETS = os.getenv("XRAY_ASSETS", "/usr/local/share/xray")
XRAY_API = os.getenv("XRAY_API", "127.0.0.1:10085")
ACCESS_LOG = Path(os.getenv("XRAY_ACCESS_LOG", "/usr/local/etc/xray/access.log"))
# Сколько байт с конца access-лога читать при подсчёте устройств.
ACCESS_TAIL_BYTES = int(os.getenv("XRAY_ACCESS_TAIL", str(2 * 1024 * 1024)))
# Куда складывать вывод ядра, чтобы при падении было что показать панели.
STDOUT_LOG = Path(os.getenv("XRAY_STDOUT_LOG", "/usr/local/etc/xray/xray-stdout.log"))
SSL_CERTFILE = os.getenv("SSL_CERTFILE", "")
SSL_KEYFILE = os.getenv("SSL_KEYFILE", "")

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    xray.start()
    try:
        yield
    finally:
        xray.stop()


app = FastAPI(
    title="VPN Panel Node Agent", docs_url=None, redoc_url=None, lifespan=lifespan
)


def require_token(authorization: str = Header(default="")) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(500, "AGENT_TOKEN не задан на ноде")
    # Сравнение в постоянном времени, чтобы токен нельзя было подобрать по таймингу.
    if not hmac.compare_digest(authorization, f"Bearer {AGENT_TOKEN}"):
        raise HTTPException(401, "Неверный токен")


class XrayProcess:
    """Супервизор дочернего процесса Xray."""

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self.started_at: Optional[float] = None
        self.last_error: str = ""
        self.config_hash: str = ""
        # Путь берётся из применённого конфига: панель решает, куда Xray
        # пишет access-лог, и агент должен читать именно этот файл.
        self.access_log: Path = ACCESS_LOG
        self._log_handle = None

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def version(self) -> str:
        try:
            output = subprocess.run(
                [XRAY_BIN, "version"], capture_output=True, text=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            self.last_error = str(exc)
            return ""
        match = re.search(r"Xray\s+([0-9][^\s(]*)", output)
        return match.group(1) if match else output.strip().splitlines()[0][:32]

    def start(self) -> None:
        if self.running:
            return
        if not XRAY_CONFIG.exists():
            self.last_error = f"нет конфига {XRAY_CONFIG}"
            return

        env = dict(os.environ, XRAY_LOCATION_ASSET=XRAY_ASSETS)
        # Вывод ядра пишем в файл, а не в трубу: причину падения Xray печатает
        # в stdout, и раньше она пропадала в DEVNULL, оставляя бесполезное
        # «xray упал». Труба тут не годится — при работе ядро пишет много,
        # буфер заполнится и процесс встанет.
        try:
            STDOUT_LOG.parent.mkdir(parents=True, exist_ok=True)
            self._log_handle = open(STDOUT_LOG, "wb")
        except OSError:
            self._log_handle = None

        try:
            self.process = subprocess.Popen(
                [XRAY_BIN, "run", "-config", str(XRAY_CONFIG)],
                env=env,
                stdout=self._log_handle or subprocess.DEVNULL,
                stderr=subprocess.STDOUT if self._log_handle else subprocess.DEVNULL,
            )
        except OSError as exc:
            self.last_error = f"не удалось запустить xray: {exc}"
            self.process = None
            return

        self.started_at = time.time()
        # Даём ядру мгновение упасть на битом конфиге, чтобы вернуть панели
        # осмысленную ошибку, а не «всё хорошо».
        time.sleep(1.0)
        if not self.running:
            self.last_error = self.output_tail() or "xray упал без объяснений"
        else:
            self.last_error = ""

    def output_tail(self, limit: int = 1200) -> str:
        """Последние строки вывода ядра — то, что оно сказало перед падением."""
        if not STDOUT_LOG.exists():
            return ""
        try:
            text = STDOUT_LOG.read_text("utf-8", errors="replace")
        except OSError:
            return ""
        # Отбрасываем шум: приветствие с версией и строки [Info] о чтении
        # конфига ничего не объясняют, а вытесняют собой саму причину.
        noise = ("Penetrates Everything", "A unified platform", "[Info]", "[Debug]")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        meaningful = [
            line
            for line in lines
            if not line.startswith("Xray ") and not any(bit in line for bit in noise)
        ]
        return " ".join(meaningful or lines)[-limit:]

    def stop(self) -> None:
        if not self.process:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None
        self.started_at = None
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            finally:
                self._log_handle = None

    def restart(self) -> None:
        self.stop()
        self.start()


xray = XrayProcess()


def _read_cpu_times() -> tuple[int, int]:
    with open("/proc/stat", "r", encoding="utf-8") as handle:
        parts = [int(value) for value in handle.readline().split()[1:]]
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    return sum(parts), idle


_cpu_snapshot = _read_cpu_times()


def cpu_percent() -> float:
    """Загрузка CPU между двумя вызовами /health."""
    global _cpu_snapshot
    total, idle = _read_cpu_times()
    prev_total, prev_idle = _cpu_snapshot
    _cpu_snapshot = (total, idle)
    delta_total = total - prev_total
    if delta_total <= 0:
        return 0.0
    return round(100.0 * (1 - (idle - prev_idle) / delta_total), 1)


def mem_percent() -> float:
    values: Dict[str, int] = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        for line in handle:
            key, _, rest = line.partition(":")
            values[key] = int(rest.split()[0])
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    if not total:
        return 0.0
    return round(100.0 * (total - available) / total, 1)


def system_uptime() -> int:
    with open("/proc/uptime", "r", encoding="utf-8") as handle:
        return int(float(handle.readline().split()[0]))


@app.get("/health", dependencies=[Depends(require_token)])
def health() -> Dict[str, Any]:
    return {
        "ok": xray.running,
        "agent_version": AGENT_VERSION,
        "xray_running": xray.running,
        "xray_version": xray.version(),
        "config_hash": xray.config_hash,
        "error": xray.last_error,
        "output": xray.output_tail(400),
        "cpu_percent": cpu_percent(),
        "mem_percent": mem_percent(),
        "uptime": system_uptime(),
        "xray_uptime": int(time.time() - xray.started_at) if xray.started_at else 0,
    }


@app.post("/config", dependencies=[Depends(require_token)])
def apply_config(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Записать новый конфиг и перезапустить Xray."""
    config = payload.get("config")
    if not isinstance(config, dict):
        raise HTTPException(400, "Ожидается поле config с объектом конфига")

    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)

    # Xray отказывается стартовать, если не может открыть файл access-лога, —
    # каталог под него надо создать заранее, иначе нода ляжет на пустом месте.
    access_log = (config.get("log") or {}).get("access")
    if isinstance(access_log, str) and access_log not in ("", "none"):
        try:
            Path(access_log).parent.mkdir(parents=True, exist_ok=True)
            Path(access_log).touch(exist_ok=True)
        except OSError as exc:
            raise HTTPException(
                400, f"не создать файл access-лога {access_log}: {exc}"
            ) from exc
        xray.access_log = Path(access_log)

    backup = XRAY_CONFIG.with_suffix(".json.bak")
    if XRAY_CONFIG.exists():
        backup.write_text(XRAY_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")

    XRAY_CONFIG.write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    xray.restart()

    if not xray.running:
        # Запоминаем причину до отката: перезапуск на старом конфиге пройдёт
        # успешно и затрёт last_error, а панели нужна именно первая ошибка.
        reason = xray.last_error or "Xray не запустился"
        if backup.exists():
            # Откатываемся на прошлый рабочий конфиг, чтобы нода не легла.
            XRAY_CONFIG.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
            xray.restart()
        raise HTTPException(400, f"Конфиг не принят Xray: {reason}")

    xray.config_hash = str(payload.get("hash") or "")
    return {
        "ok": True,
        "xray_running": xray.running,
        "xray_version": xray.version(),
        "config_hash": xray.config_hash,
    }


@app.post("/restart", dependencies=[Depends(require_token)])
def restart() -> Dict[str, Any]:
    xray.restart()
    return {"ok": xray.running, "error": xray.last_error}


def _exit_for_restart() -> None:
    """Выйти, чтобы systemd поднял агента с новым кодом."""
    time.sleep(1.0)  # успеть отдать ответ панели
    xray.stop()
    # os._exit, а не sys.exit: мы в отдельном потоке, обычный выход его не
    # завершит процесс. Restart=always в юните поднимет агента заново.
    os._exit(0)


@app.post("/update", dependencies=[Depends(require_token)])
def update(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Заменить собственный код на присланный панелью и перезапуститься.

    Обновлять агента руками через ssh на каждой ноде — то, из-за чего он
    месяцами остаётся старым, а панель получает бесполезные сообщения об
    ошибках. Код приходит от панели, с которой агент и так связан токеном,
    так что отдельного канала доверия здесь не появляется.
    """
    source = payload.get("source")
    if not isinstance(source, str) or not source.strip():
        raise HTTPException(400, "Ожидается поле source с кодом агента")

    # Две проверки перед подменой: это действительно агент и он хотя бы
    # компилируется. Записать сюда обрывок файла — значит потерять ноду.
    if "class XrayProcess" not in source:
        raise HTTPException(400, "Присланный код не похож на агента")
    try:
        compile(source, "agent.py", "exec")
    except SyntaxError as exc:
        raise HTTPException(400, f"Присланный код не компилируется: {exc}")

    target = Path(__file__).resolve()
    try:
        backup = target.with_suffix(".py.bak")
        backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        target.write_text(source, encoding="utf-8")
    except OSError as exc:
        raise HTTPException(500, f"не удалось записать {target}: {exc}")

    threading.Thread(target=_exit_for_restart, daemon=True).start()
    return {
        "ok": True,
        "previous_version": AGENT_VERSION,
        "version": payload.get("version"),
        "path": str(target),
        "restarting": True,
    }


def _query_stats(reset: bool) -> Dict[str, int]:
    command = [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}"]
    if reset:
        command.append("-reset")
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        raise HTTPException(503, f"Xray API недоступен: {result.stderr.strip()[:300]}")
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(503, f"Не разобрать ответ Xray API: {exc}") from exc
    return {
        item["name"]: int(item.get("value", 0) or 0)
        for item in data.get("stat", [])
        if item.get("name")
    }


# Xray пишет строки вида:
# 2026/08/07 21:28:39.492233 from 127.0.0.1:54342 accepted tcp:example.com:443 \
#   [VLESS-REALITY >> DIRECT] email: user_1
# Адрес идёт сразу после "from", без указания протокола; у IPv6 он в скобках.
# Строки служебного api-inbound не содержат email и отсекаются сами.
_ACCESS_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})[^ ]* from "
    r"(?:tcp:|udp:)?\[?(?P<ip>[0-9a-fA-F.:]+?)\]?:\d+ .*email: (?P<email>\S+)"
)


@app.get("/online", dependencies=[Depends(require_token)])
def online(minutes: int = Query(default=5, ge=1, le=1440)) -> Dict[str, Any]:
    """Кто и с каких адресов подключался за последние `minutes` минут.

    Считается по access-логу Xray. Панель по этим данным показывает число
    устройств и следит за лимитом.
    """
    log_path = xray.access_log
    if not log_path.exists():
        return {"users": {}, "log": str(log_path), "available": False}

    # Читаем хвост файла: лог может быть большим, а нужны свежие строки.
    try:
        with open(log_path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - ACCESS_TAIL_BYTES))
            tail = handle.read().decode("utf-8", "replace")
    except OSError as exc:
        raise HTTPException(503, f"не читается access-лог: {exc}") from exc

    since = time.time() - minutes * 60
    users: Dict[str, set] = {}

    for line in tail.splitlines():
        match = _ACCESS_RE.match(line)
        if not match:
            continue
        try:
            moment = time.mktime(time.strptime(match.group("ts"), "%Y/%m/%d %H:%M:%S"))
        except ValueError:
            continue
        if moment < since:
            continue
        users.setdefault(match.group("email"), set()).add(match.group("ip"))

    return {
        "users": {email: sorted(ips) for email, ips in users.items()},
        "log": str(log_path),
        "available": True,
        "window_minutes": minutes,
    }


@app.get("/stats", dependencies=[Depends(require_token)])
def stats(reset: bool = Query(default=True)) -> Dict[str, Any]:
    """Счётчики трафика.

    reset=true (по умолчанию) обнуляет счётчики в Xray, поэтому панель
    получает дельту с прошлого опроса и просто прибавляет её.
    """
    raw = _query_stats(reset)

    users: Dict[str, Dict[str, int]] = {}
    inbounds: Dict[str, Dict[str, int]] = {}
    total_up = total_down = 0

    for name, value in raw.items():
        parts = name.split(">>>")
        if len(parts) != 4:
            continue
        kind, target, _, direction = parts
        if direction not in ("uplink", "downlink"):
            continue
        if kind == "user":
            users.setdefault(target, {"uplink": 0, "downlink": 0})[direction] += value
        elif kind == "inbound":
            inbounds.setdefault(target, {"uplink": 0, "downlink": 0})[
                direction
            ] += value
            if target != "api":
                if direction == "uplink":
                    total_up += value
                else:
                    total_down += value

    return {
        "users": users,
        "inbounds": inbounds,
        "total": {"uplink": total_up, "downlink": total_down},
    }


def main() -> None:
    if not AGENT_TOKEN:
        raise SystemExit("Переменная AGENT_TOKEN обязательна")
    ssl_kwargs = {}
    if SSL_CERTFILE and SSL_KEYFILE:
        ssl_kwargs = {"ssl_certfile": SSL_CERTFILE, "ssl_keyfile": SSL_KEYFILE}
    uvicorn.run(app, host=AGENT_HOST, port=AGENT_PORT, log_level="info", **ssl_kwargs)


if __name__ == "__main__":
    main()
